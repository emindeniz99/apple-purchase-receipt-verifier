# The server engine's client on HttpURLConnection (2026-10-02)

**Question.** The Java `-wasm` artifact's server engine talked to
`aprv-server` through a hand-written HTTP/1.1 client (`HttpConn`, one
write per request with `TCP_NODELAY`), kept because the 2026-09-25 spike
measured `HttpURLConnection` about 1.5 ms slower per POST
([rust-core spikes][spikes], "Sidecar"). The owner's Q17 replaces it with
the JDK's `HttpURLConnection`. Which way of sending the POST body keeps
the engine's speed and the answers its tests pin: streamed with its
length (`setFixedLengthStreamingMode`), or buffered (the default)? This
feeds DECISIONS.md R17's amendment of 2026-10-02.

**Versions.** OpenJDK 21.0.10 and Temurin 1.8.0_504-b01, Maven 3.9.11,
4 vCPUs shared with a concurrent Rust build (so one run per cell, and
differences under about 0.5 ms are noise). `aprv-server` built with
`rust/server/scripts/build-static.sh` for `x86_64-unknown-linux-musl`
from base commit `fce1407`, embedding a component with SHA-256
`6db3b911…d850a8`; the binary's SHA-256 is `bee51a30…430abd`. Code and
commands are in `2026-10-02-java-httpurlconnection/`.

## What the JDK does with each mode

Read from the JDK 8 sources (`sun/net/www/protocol/http/HttpURLConnection.java`,
`sun/net/www/http/HttpClient.java`) and confirmed by the runs below:

- **Buffered.** The body is held in memory, and the request line, the
  headers and the body go to the socket through one 8 KiB
  `BufferedOutputStream` and one flush. A body that fits with its
  headers (the 7,556-byte g5 receipt does, with about 400 bytes of
  headers) leaves in one write. When the connection fails before the
  status line arrives, other than by a read timeout,
  `HttpClient.parseHTTP` sends the request once more on a new
  connection: `sun.net.http.retryPost`, true by default.
- **Streamed.** `getOutputStream()` writes and flushes the headers before
  the body exists, so every POST is two writes, and Nagle's algorithm
  holds the second back until the server's delayed ACK. `parseHTTP` never
  resends a streamed request. A 401 to a streamed request makes
  `getInputStream0` disconnect and throw `HttpRetryException` before the
  body is read, so the server's problem document is lost.

## Results

`ServerEngineTest.roundTripTimes`: the g5 receipt through a managed child,
1,000 calls on one thread after 300 warm-up calls, then 4 threads for
5 s; `GET /healthz` 5,000 times. The `BENCH` lines of each run:

| Client | JVM | g5, 1 thread: mean / p50 / p99 (µs) | 4 threads (calls/s) | `GET /healthz` (µs) |
|---|---|---|---:|---:|
| hand-written (`fce1407`) | 21 | 2,374 / 2,152 / 4,618 | 1,159 | 26.8 |
| hand-written (`fce1407`) | 8 | 2,123 / 2,074 / 3,383 | 1,186 | 54.0 |
| `HttpURLConnection`, buffered | 21 | 2,481 / 2,344 / 4,074 | 1,190 | 74.1 |
| `HttpURLConnection`, buffered | 8 | 2,018 / 1,940 / 3,318 | 1,198 | 58.4 |
| `HttpURLConnection`, streamed | 21 | 3,911 / 3,717 / 5,516 | 862 | 57.1 |
| `HttpURLConnection`, streamed | 8 | 3,938 / 3,768 / 5,640 | 848 | 69.1 |

A second buffered run on JDK 21 gave 2,529 / 2,307 / 4,723 µs and
1,146 calls/s.

`LargeBodyBench.java`, the same managed child, 1,000 calls each after 300
warm-up calls, mean / p50 in µs:

| Client | JVM | g5, 7,556 bytes | legacy, 105,472 bytes |
|---|---|---|---|
| hand-written (`fce1407`) | 21 | 2,276 / 2,156 | 12,709 / 11,710 |
| hand-written (`fce1407`) | 8 | 2,455 / 2,197 | 11,901 / 11,456 |
| `HttpURLConnection`, buffered | 21 | 2,918 / 2,513 | 12,934 / 11,812 |
| `HttpURLConnection`, buffered | 8 | 2,630 / 2,384 | 12,368 / 11,765 |
| `HttpURLConnection`, streamed | 21 | 3,949 / 3,748 | 15,467 / 13,689 |
| `HttpURLConnection`, streamed | 8 | 3,769 / 3,443 | 15,203 / 13,767 |

The answers: every buffered run passes all of `ServerEngineTest`,
`ServerUrlTest` and `ServerConformanceCasesTest`. Every streamed run fails
`aRequestWithoutTheTokenOrWithAWrongOneIsRefused` with
`expected: <UNAUTHORIZED> but was: <HTTP_401>`: the 401 arrives, its body
does not.

## Verdict

Buffered. Against the hand-written client it ranges from 0.1 ms faster
to 0.6 ms slower on g5 across the four runs, is 0.2 to 0.5 ms slower on
the 105 KB receipt, matches it on 4 threads, and reads a 401's problem
document. Streamed costs 1.0 to 1.9 ms a call on g5 (about 30% fewer
calls per second on 4 threads) and 2.5 to 3.3 ms on the 105 KB receipt,
the stall the 2026-09-25 spike measured, and loses the 401's body.

The cost of buffered is the JDK's one resend of a POST whose connection
failed before the status line. It cannot change a verdict: verification
has no side effects, and the request carries its own `X-Aprv-Now-Ms`, so
the resend asks the same question at the same instant. It cannot double
a wait either, because a read timeout is not resent.
`ServerConnection.send` keeps its own three attempts, which the JDK's
resend does not replace: those restart a child that died.

## Where this stops holding

- One machine, one run per cell, shared CPUs; Linux loopback only. A
  `url` source across a real network was not measured.
- A buffered body with its headers over 8 KiB leaves in two writes as
  well; the 105 KB receipt shows that cost to be small next to its
  verification, but bodies between 8 KiB and about 64 KiB were not
  measured.
- The JDK behaviour is read from the JDK 8 sources and observed on JDK 8
  and 21. The `-wasm` artifact runs the server engine on Java 8 and
  Endive on Java 11 and later, so other JDKs reach this code only when a
  caller picks `Engine.server(...)`.

[spikes]: 2026-09-25-rust-core-spikes.md
