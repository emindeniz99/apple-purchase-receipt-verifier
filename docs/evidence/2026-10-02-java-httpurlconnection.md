# The server engine's client on HttpURLConnection (2026-10-02)

**Outcome (2026-10-03).** Reverted before it merged. The owner put the
hand-written `HttpConn` back on the same pull request, hardened, for the
reasons this note records itself: on Java 8 the JDK answers a 401
`Basic` challenge with the default `Authenticator`'s credentials and has
no per-connection switch to stop it (Authentication), it resends a POST
inside each of the engine's attempts (Resends), and a SOCKS proxy still
reaches it (SOCKS). The comparison that decided it, with `HttpConn`,
Apache HttpClient 5 and `java.net.http` against the same servers, is
[the HTTP client options note][options]; DECISIONS.md R17 records both
dates. The rest of this note is as written on 2026-10-02.

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
commands are in `2026-10-02-java-httpurlconnection/`. The resend and
SOCKS probes ran later the same day on the client as amended after
review (a pinned TLS factory and hostname verifier, and framed bodies
only), on the same two JVMs; they need no server. The authentication
probe and the framing tests ran after a second review on those two and
on Temurin 25.0.4.1+1 and 27+35, the newest JDKs CI's `java-wasm-endive`
job runs.

## What the JDK does with each mode

Read from the JDK 8 sources (`sun/net/www/protocol/http/HttpURLConnection.java`,
`sun/net/www/http/HttpClient.java`, `sun/net/NetworkClient.java`), checked
against the same files in `openjdk/jdk21u`, and confirmed by the runs
below:

- **Buffered.** The body is held in memory, and the request line, the
  headers and the body go to the socket through one 8 KiB
  `BufferedOutputStream` and one flush. A body that fits with its
  headers (the 7,556-byte g5 receipt does, with about 400 bytes of
  headers) leaves in one write. When the connection fails before the
  status line arrives, other than by a read timeout,
  `HttpClient.parseHTTP` sends the request once more on a new
  connection: `sun.net.http.retryPost`, true by default. Separately,
  when writing the request fails, `HttpURLConnection.writeRequests`
  sends it once more on a new connection whatever that property says,
  and that new connection may still take the `parseHTTP` resend.
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

The answers: every buffered run passes `ServerEngineTest` and
`ServerUrlTest`, and the full `mvn verify` on each JVM (the README's
`run ... verify` line) passes `ServerConformanceCasesTest`'s 385 cases
too. Every streamed run fails
`aRequestWithoutTheTokenOrWithAWrongOneIsRefused` with
`expected: <UNAUTHORIZED> but was: <HTTP_401>`: the 401 arrives, its body
does not.

### Resends

`ResendProbe.java`: one `ServerConnection.send` of a 4 MiB POST to a
server that resets a connection without reading it (so the write
fails), reads the whole request on the next one and closes before a
status line, then resets the third, in a cycle. Its three attempts
opened 9 connections and the server read 3 whole requests in both runs
on Java 8 and in one of two on JDK 21; the other JDK 21 run opened 6 and
read 2, because whether the reset lands before the write is a race. A
server that reads every request and closes before the status line
receives it 6 times, twice per attempt; `ServerHttpTest` pins that
count.

### Authentication

`AuthenticatorProbe.java`: a server that answers every request with 401
and `WWW-Authenticate: Basic`, a default `Authenticator` that hands out
credentials, and one buffered POST per mode. The same on all four JDKs
where the mode exists:

| Mode | Java 8 | JDK 21, 25, 27 |
|---|---|---|
| as the engine sent it before the fix | 401, body lost; 20 connections, 19 with `Authorization: Basic` | the same |
| with an `Authorization: Bearer` header set by the caller | the same as above | the same as above |
| `setAuthenticator` with an `Authenticator` that has no credentials | no such method | 401 with its body; 1 connection, no `Authorization` |

Read from `sun/net/www/protocol/http/HttpURLConnection.java` in JDK 8
and JDK 21: `getInputStream0` sets `isUserServerAuth` when the caller set
`Authorization`, but reads it only to keep that header after a
successful response. On a 401 it calls `getServerAuthentication`, which
asks the Authenticator (the default one, or the connection's own on 9
and later) and on an answer sets `Authorization` over the caller's and
loops, while `redirects < http.maxRedirects`. Each turn is a new
connection carrying the body and `X-Aprv-Token`. After the last it
throws `ProtocolException` ("Server redirected too many times"):
`getResponseCode` still reads 401 from the headers, but
`getErrorStream` is null, so the engine sees a 401 whose body falls
short of its `Content-Length` and tries again: 60 sends in a call on
Java 8.
`aprv-server`'s own 401 carries no challenge, so it never takes that
path. The engine now sets the per-connection `Authenticator` on 9 and
later; Java 8 keeps the 60. `ServerHttpTest` pins both counts.

### Framing

The JDK de-chunks a body only when the one `Transfer-Encoding` value it
looks up is exactly `chunked` (`HttpClient.parseHTTP`, same lookup as
`getHeaderField`), case aside. `gzip, chunked` reaches the caller still
chunked and read to the close; `xchunked` with a `Content-Length` is read
by the length. The engine refuses any other value. A body that ends
before its `Content-Length` reads short on JDK 8 and 21, and on 25 and 27
`MeteredStream` throws `IOException: Premature EOF`; the engine treats
both as a connection that closed inside the response (`EOFException`),
so the attempt is retried the same way on every JDK.

### HTTPS

Read from `sun/net/www/protocol/https/HttpsClient.java` in JDK 8 and
JDK 21, where `afterConnect` is the same on this point. With
`HttpsURLConnection`'s default hostname verifier, the JDK sets the
socket's endpoint identification to `HTTPS` and the trust manager checks
the name in the handshake. With any other verifier, it leaves that unset
and, after the handshake, `checkURLSpoofing` matches the certificate
against the host by RFC 2818 (`HostnameChecker`, `TYPE_TLS`), asking the
verifier only on a mismatch and closing the socket when it says no.
`afterConnect` runs from `connect()`, before `writeRequests`, so either
way no request byte is written to a server that fails. The engine's
verifier always says no, and its socket factory is the default
`SSLContext`'s, so neither of `HttpsURLConnection`'s replaceable JVM-wide
defaults takes part. The hand-written client took
`SSLSocketFactory.getDefault()`, which a class named by the
`ssl.SocketFactory.provider` security property replaces; this one does
not follow it, and `HttpsClient` applies the `https.protocols` and
`https.cipherSuites` system properties to its sockets. `ServerHttpTest` observes it on both JVMs: a
self-signed server under a trust-all default factory and an allow-all
default verifier, and a trusted certificate for another name, are each
refused without the server reading a byte of the request.

### SOCKS

`SocksProbe.java`: a default `ProxySelector` that answers `socket://`
with a SOCKS proxy (a listener that accepts and closes) and every other
URI with a direct connection, then one request per scheme to a closed
port, opened with `Proxy.NO_PROXY`:

| Connection | Java 8 | JDK 21 |
|---|---|---|
| `HttpURLConnection`, `http` | reaches the SOCKS listener | direct |
| `HttpURLConnection`, `https` | reaches the SOCKS listener | reaches the SOCKS listener |
| `new Socket()`, as the hand-written client connected | reaches the SOCKS listener | reaches the SOCKS listener |

Java 8's `NetworkClient.createSocket` is `new Socket()`, which asks the
selector; JDK 21's is `new Socket(Proxy.NO_PROXY)`. An `https`
connection gets its socket from the TLS socket factory's `createSocket()`
on both, which asks. `NO_PROXY` keeps out HTTP proxies only.

## Verdict

Buffered. Against the hand-written client it ranges from 0.1 ms faster
to 0.6 ms slower on g5 across the four runs, is 0.2 to 0.5 ms slower on
the 105 KB receipt, matches it on 4 threads, and reads a 401's problem
document. It is slower on one call: `GET /healthz` on JDK 21 went from
26.8 to 74.1 µs (on Java 8, 54.0 to 58.4 µs), the per-request cost of
`HttpURLConnection` with no verification to hide it. A health probe is
not on a verdict's path, so it does not change the choice. Streamed
costs 1.0 to 1.9 ms a call on g5 (about 30% fewer calls per second on 4
threads) and 2.5 to 3.3 ms on the 105 KB receipt, the stall the
2026-09-25 spike measured, and loses the 401's body.

The cost of buffered is the JDK's resends: up to two more sends inside
each of the engine's three attempts, nine connections in all
(Resends, above). On Java 8 a 401 challenge that the JVM's default
`Authenticator` answers adds up to 19 sends an attempt, with its
credentials (Authentication, above); that is HttpURLConnection's, not
buffering's, and Java 9 and later are closed to it. They cannot change a verdict: verification has no side
effects, and the request carries its own `X-Aprv-Now-Ms`, so a resend
asks the same question at the same instant. They cannot double a wait
either, because a read timeout is not resent.
`ServerConnection.send` keeps its own three attempts, which the JDK's
resends do not replace: those restart a child that died.

## Where this stops holding

- One machine, one run per cell, shared CPUs; Linux loopback only. A
  `url` source across a real network was not measured.
- A buffered body with its headers over 8 KiB leaves in two writes as
  well; the 105 KB receipt shows that cost to be small next to its
  verification, but bodies between 8 KiB and about 64 KiB were not
  measured.
- The JDK behaviour is read from the JDK 8 and JDK 21 sources and
  observed on JDK 8 and 21; the authentication probe and
  `ServerHttpTest` also ran on 25 and 27. JDKs 9 to 20 and 22 to 24
  were not run.
- Only `Basic`, which goes through the `Authenticator`, was probed. Not
  probed: `Negotiate` and NTLM, which can use the platform's own
  credentials (a Kerberos ticket cache, Windows logon) where the JDK is
  set up for them. The
  `-wasm` artifact runs the server engine on Java 8 and Endive on Java 11
  and later, so other JDKs reach this code only when a caller picks
  `Engine.server(...)`.
- The latency runs predate the review's changes to the client (the TLS
  factory and verifier, which plain `http` does not touch, and the
  framing checks, a header lookup and a length comparison per call);
  they were not run again.

[spikes]: 2026-09-25-rust-core-spikes.md
[options]: 2026-10-02-java-http-options.md
