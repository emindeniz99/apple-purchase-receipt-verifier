# Java: what a cap-sized receipt costs before trust

Date: 2026-10-05. Feeds owner decision Q55 (Java has no node budget before
the signature) and the residual-risk sentence in THREAT-MODEL.md §3.7.
Sources and commands:
[`2026-10-05-java-presignature-parse-cost/`](2026-10-05-java-presignature-parse-cost/).

## Question

The Rust core walks the envelope and the payload under a budget of 100,000
values before it decodes anything. Java has no such budget: BouncyCastle
parses the whole CMS envelope, and `ReceiptDecoder.readTopLevel` decodes
the whole top-level attribute SET to find the creation date, both before
any signer is matched. How much heap and time does a receipt at the
3,145,728-character cap cost there, and how does that compare with the
16 to 18 MiB the core peaks at for the same shapes?

## Setup

- OpenJDK 21.0.10 (Ubuntu build), 4 vCPU, 16 GB RAM, one thread. G1
  unless stated; the bisection was repeated with `-XX:+UseSerialGC`.
- bcprov, bcutil and bcpkix 1.86, jackson-core 2.22.3.
- The library at `refactor/java-single-parse` (the payload parsed once),
  and for comparison `ReceiptCore` and `ReceiptDecoder` from `main` at
  `3a31f14` (parsed twice: once before the signature for the date, again
  after it).

Inputs, written by `PresignatureCost make`, all signed by one `TestPki`
leaf:

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
1 MiB three times. From `results/branch-g1.txt`,
`results/branch-serial.txt` and `results/main-g1.txt`.

| Input | Roots | Verdict | ms per call | MiB allocated per call | Smallest `-Xmx`, MiB |
|---|---|---|---|---|---|
| `baseline` | TestPki | verifies | 4.7, 5.7, 5.3 | 0.3 | 13 |
| `baseline` | Apple | `UNTRUSTED_CHAIN` | 1.2, 1.2, 1.7 | 0.1 | 13 (Serial: 11) |
| `tiny-attributes` | TestPki | verifies | 257, 374, 263 | 168.2 | 79 |
| `tiny-attributes` | Apple | `UNTRUSTED_CHAIN` | 318, 208, 210 | 144.2 | 79 |
| `unsigned-attribute` | TestPki | verifies | 187, 199, 188 | 73.0 | 27 |
| `unsigned-attribute` | Apple | `UNTRUSTED_CHAIN` | 186, 188, 187 | 72.8 | 27 |

Every bisection gave the same figure three times, and Serial GC the same
as G1 except the one baseline row marked. The heap a verified
`tiny-attributes` result keeps after GC is 26.4 to 26.5 MiB: its 195,562
unknown attributes, returned to the caller. The other results keep under
1 MiB.

Against a genuine receipt's 13 MiB, the `tiny-attributes` receipt needs
66 MiB more heap at its peak: 22 times its 3.0 MiB of base64, 29 times
its 2.25 MiB of DER. That peak is reached before trust, since the
`UNTRUSTED_CHAIN` run needs the same 79 MiB. The 144 MiB it allocates
before trust is 48 times the input. The `unsigned-attribute` receipt
needs 14 MiB more, about 5 times its input. Every call averaged under
0.5 s.

### Parsing once (Q55 a)

The same `run.sh` on `main`'s two classes, from `results/main-g1.txt`:

| Input | Roots | ms per call, main | ms per call, branch | MiB allocated, main | MiB allocated, branch |
|---|---|---|---|---|---|
| `tiny-attributes` | TestPki | 402, 461, 413 | 257, 374, 263 | 294.4 | 168.2 |
| `tiny-attributes` | Apple | 191, 171, 193 | 318, 208, 210 | 144.2 | 144.2 |
| `unsigned-attribute` | TestPki | 204, 206, 198 | 187, 199, 188 | 73.0 | 73.0 |

Dropping the second parse cuts the allocation of a verified cap-sized
receipt of tiny attributes from 294 to 168 MiB and its time by about a
third. It does not move the peak (79 MiB on both), because the second
parse on `main` ran after the first one's tree was garbage. The work
before trust is unchanged, as it should be: the same decode, now kept.
The baseline timings vary between the two runs by more than the change
could explain (main 12 to 13 ms for the verified baseline, branch 5 to
6 ms), so the machine was not quiet; the allocation figures are the
steady ones.

### Against the core

The core's figures for the equivalent shapes, from
docs/rust-core/THREAT-MODEL.md §5 and
[`2026-09-29-core-review-fixes.md`](2026-09-29-core-review-fixes.md):
a signerless receipt of 3 MiB of tiny attributes grows `aprv.wasm`'s linear
memory from 1.9 to 16.1 MiB in 16.5 to 26.1 ms, and 1.17 million empty
SEQUENCEs in an unsigned attribute are refused as `MALFORMED` by the
value budget in 10.2 ms and 14.5 MB. Java takes 66 MiB more heap and about
0.2 s for the first shape, which it decodes in full, and 14 MiB and about
0.19 s for the second, which it parses and verifies.

## Verdict

The `tiny-attributes` shape crosses the bar the owner set for "a real
amplification problem" (more than 20 times the input): 22 times the base64
in peak heap, all of it spent before trust. The time is far below the 2 s
bar. No code was added for it; the options went to the owner with this
change. Only the input cap bounds the cost, and
java/README.md already tells hosts to cap body size and concurrency.

## Where this stops holding

- One machine, one JDK, one thread. Time scales with the machine;
  allocation and the bisected heap are the steady figures.
- The smallest `-Xmx` includes the JVM's own floor (13 MiB here) and the
  caller's copy of the base64 string, so the growth over the baseline, not
  the absolute figure, is what an input costs. It is a fresh JVM's first
  call, with the interpreter's allocation pattern.
- bcprov 1.86. A BouncyCastle that builds its tree differently changes
  every figure.
- Two shapes. A shape that makes BouncyCastle hold more per byte than an
  attribute of 12 bytes or an empty SEQUENCE of 2 was not searched for.
