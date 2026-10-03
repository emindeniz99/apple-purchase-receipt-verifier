# How the server engine should talk to aprv-server (2026-10-02)

**Outcome (2026-10-03).** The owner took the verdict below: the engine
keeps `HttpConn`. `httpconn-hardening.patch` landed on PR #222 in two
commits: f1bbeff (the framing checks and `Proxy.NO_PROXY`, together
with the fix for the IPv6 `Host` header that section 2 read but could
not run) and 6d3231d (a TLS context per connection). Later commits on
the same PR also require hex chunk sizes and CRLF line ends (b47892b)
and leave an IPv6 zone id out of `Host` (2947e30). The sections below
measured `HttpConn` as it is on `main`, before any of them;
DECISIONS.md R17 describes the client after them.

**Question.** The Java `-wasm` artifact's server engine reaches
`aprv-server` over HTTP/1.1, either a managed child on loopback (with a
per-process `X-Aprv-Token`) or a `ServerSource.url` the caller runs (http
or https). On `main` the client is hand-written (`HttpConn`, 271 lines).
PR #222 replaced it with `HttpURLConnection` and found that the JDK
client inherits JVM-wide state that cannot all be switched off, on Java 8
least of all ([HttpURLConnection][huc]). Which client should the engine
use, or should the managed child drop HTTP for stdin and stdout? This
feeds DECISIONS.md R17.

The owner's tests for an answer: no hand-written code where a platform
or library client suffices; never two things doing the same job;
top-quality libraries; and nothing outside the program may change a
verdict.

**Versions.** OpenJDK 21.0.10 and Temurin 1.8.0_504-b01, Maven 3.9.11,
4 shared vCPUs. Apache HttpClient 5.6.4 with HttpCore 5.4.3 (the versions
httpclient5 5.6.4's POM names), SLF4J 1.7.36. `aprv-server` built with
`rust/server/scripts/build-static.sh` for `x86_64-unknown-linux-musl` from
this branch's base (`756b1d7`), embedding the component `6db3b911…d850a8`;
the binary is 12,121,040 bytes, SHA-256 `bee51a30…430abd`, the same
binary PR #222's note measured. Code and commands:
[2026-10-02-java-http-options/](2026-10-02-java-http-options/).

## 1. The clients against the same misbehaving servers

`ClientMatrix.java` sends one POST from each client to a raw-socket server
that misbehaves on purpose, or under JVM-wide state that other code or a
`-D` flag can set, on JDK 21 and Java 8 (`results/matrix.txt`).
"hardened" is configured as the engine would configure it: HttpClient 5
through `HttpClients.custom()` with redirects, automatic retries,
content decoding, cookies and the auth cache off; `java.net.http` with
HTTP/1.1, `NO_PROXY`, no redirects and an `SSLContext` of its own. Both
adapters add the two checks neither library makes: a body framed by
neither `Content-Length` nor chunks is refused, and a body over the
64 MiB cap is refused rather than cut. ✗ marks an answer the engine must
not accept, or state that reaches it.

| Scenario | `HttpConn` (main) | HttpClient 5, hardened | HttpClient 5, `createDefault()` | `java.net.http`, hardened | `java.net.http`, default |
|---|---|---|---|---|---|
| Body short of `Content-Length`; chunk cut short | refused | refused | refused | refused | refused |
| No `Content-Length`, no chunks (read to close) | refused | refused (adapter) | ✗ accepted | refused (adapter) | ✗ accepted |
| `Transfer-Encoding: gzip, chunked`, complete body | ✗ accepted, de-chunked | refused | refused | refused (adapter) | ✗ accepted, still chunked |
| `Transfer-Encoding: xchunked`, complete chunks | ✗ accepted as chunked | refused | refused | refused (adapter) | ✗ accepted, still chunked |
| Two `Content-Length`s, 2 and 4 | ✗ accepted, the last (4) | refused | refused | ✗ accepted, the first | ✗ accepted, the first |
| `Content-Length` and `chunked` both | ✗ accepted, connection kept | ✗ accepted | ✗ accepted | refused | refused |
| `Content-Length : 2` (space before the colon) | ✗ accepted | refused | refused | refused | refused |
| `Content-Length: +2` | accepted | accepted | accepted | accepted | accepted |
| `Content-Encoding: gzip` | raw bytes | raw bytes | decoded | raw bytes | raw bytes |
| Declared length over the cap, no body | refused in 0–1 ms | refused in 1–2 ms | waits for its 3-minute read timeout | refused in 6 ms | not run |
| Body dripped 1 byte / 700 ms, 3 s read timeout | accepted after 5.6 s | accepted after 5.6 s | not run | accepted after 5.6 s | not run |
| Closed before the status line: requests the server read | 1 | 1 | 1 | 1 | 1 |
| 401 `Basic` challenge, default `Authenticator` set | 401 returned, not asked | 401 returned, not asked | 401 returned, not asked | 401 returned, not asked | 401 returned, not asked |
| 307 to another server | returned | returned | ✗ followed, token sent there | returned | returned |
| Default `ProxySelector` sends `socket://` to SOCKS | ✗ SOCKS | ✗ SOCKS | ✗ SOCKS | direct | ✗ HTTP proxy, token sent there |
| `socksProxyHost` etc. as system properties, loopback target | direct | direct | direct | direct | direct |
| The same, non-loopback target (a `url` source) | ✗ SOCKS | ✗ SOCKS | ✗ SOCKS | direct | ✗ HTTP proxy, token sent there |
| TLS: certificate the JVM trusts, for the host | accepted | accepted | accepted | accepted | accepted |
| TLS: trusted, another name; also with an allow-all `HttpsURLConnection` default verifier | refused, no byte sent | refused | refused | refused | refused |
| TLS: self-signed, `HttpsURLConnection` defaults trust all | refused | refused | refused | refused | refused |
| TLS: self-signed, `SSLContext.setDefault(trust all)` | ✗ accepted, token sent | refused | refused | refused | ✗ accepted, token sent |
| TLS: trusted, another name, `-Djdk.internal.httpclient.disableHostnameVerification` (JDK 21) | refused | refused | refused | ✗ accepted, token sent | ✗ accepted, token sent |
| `-D` logging flags only: token / request body on stderr | no / no | ✗ yes / yes (SLF4J debug) | — | ✗ yes / no (`jdk.httpclient.HttpClient.log`) | — |

Java 8 gives the same answers for `HttpConn` and HttpClient 5 in every
row; `java.net.http` does not exist there. On loopback the JDK's default
proxy selector never proxies, even with `socksNonProxyHosts` and
`http.nonProxyHosts` set to something else, so the managed child is
reached directly whatever the system properties say; only a replaced
`ProxySelector` (code in the JVM) moves it.

What the table says about each library, read with the sources:

- **HttpClient 5** is the strictest parser here: one `Transfer-Encoding`
  of exactly `chunked` or a refusal, a second `Content-Length` refused
  (`DefaultContentLengthStrategy`), a space before a colon refused, and
  header counts and line lengths bounded. Hardened, it reads no system
  property (`HttpClientBuilder` and `PoolingHttpClientConnectionManagerBuilder`
  read `http.keepAlive`, `http.agent`, `https.protocols`,
  `https.cipherSuites` and the proxy and `Authenticator` settings only
  after `useSystemProperties()`), and its TLS is
  `SSLContexts.createDefault()`, a context of its own. It still opens
  every plain socket with `new Socket()` (`DefaultHttpClientConnectionOperator.PLAIN_SOCKET_FACTORY`),
  so a `ProxySelector` or `socksProxyHost` carries it to SOCKS like
  `HttpConn`; changing that takes the `DefaultHttpClientConnectionOperator`
  constructor with a `DetachedSocketFactory` and the `@Internal`
  `PoolingHttpClientConnectionManager` constructor. Defaults the engine
  must turn off: redirects (the 307 carried the token to another host),
  content decoding (with Commons Compress, zstd-jni or brotli4j on the
  classpath, 5.6's `ContentCodecRegistry` registers their decoders, the
  last two JNI), and reading to close. `EntityUtils.toByteArray(entity,
  max)` cuts a body at `max` without saying so, and a handler that throws
  leaves `execute()` draining the rest of the body until the read timeout
  unless it cancels the request first (`Hc5Clients.java`).
- **`java.net.http`** is direct by default once given `NO_PROXY`, but
  `jdk.internal.httpclient.disableHostnameVerification`, a system
  property read once per JVM, turns host name checks off for every
  client, with no per-client override: with it, a certificate for
  `other.example` was accepted for `127.0.0.1` and the token sent. It
  takes the first of two `Content-Length`s, and the default client hands a
  `gzip, chunked` body over still chunked. Java 11 and later only.
- **`HttpConn`** never consults an `Authenticator`, never follows a
  redirect, never resends inside an attempt, never decodes, logs nothing,
  and refuses an over-cap length from the headers. Its gaps are six, and
  all are in its own lines: the transfer-coding test is `contains("chunked")`;
  a repeated `Content-Length` overwrites the first; `Content-Length` with
  `chunked` is accepted and the connection kept; whitespace before a colon
  is trimmed away; the socket is `new Socket()`, which asks the default
  `ProxySelector`; and TLS comes from `SSLSocketFactory.getDefault()`,
  which follows `SSLContext.setDefault` and the `ssl.SocketFactory.provider`
  security property. PR #222's client has the last one too: its R17 text
  uses "the default `SSLContext`'s socket factory".

No client bounds a call's total time: a body that arrives a byte at a
time under the read timeout is waited for (5.6 s here; with the engine's
60 s read timeout, without end). `java.net.http`'s request timeout ends
at the response headers.

## 2. PR #222's tests against `HttpConn`

`HttpConnServerHttpTest.java` is PR #222's `ServerHttpTest` with
`ServerConnection.exchange` replaced by an `HttpConn` exchange, and with
the expectations the PR wrote around JDK behaviour stated as the property
instead (1 request per attempt rather than the JDK's 6; a 401 with its
body on every JDK; any refusal of the two odd transfer codings rather
than the JDK's message). One test needed a change of method, not of
property: `HttpConn` checks the name inside the handshake, so the server
never completes one, where the PR's client checks it after; the test now
asserts only that the server read nothing. Six tests are new: a complete
body under `gzip, chunked`, `xchunked` and `chunked, chunked`; two
`Content-Length`s; whitespace before the colon; `Content-Length` with
`chunked` must not leave the connection reusable; a default
`ProxySelector`; and `SSLContext.setDefault(trust all)`.

| | JDK 21 | Temurin 8 |
|---|---|---|
| main's `HttpConn` | 12 of the PR's 12 pass; 5 new fail, 1 errors (the SOCKS connect) | the same |
| with `httpconn-hardening.patch` | 18 of 18; with every `Server*Test` (385 conformance cases through the real binary among them), `mvn` exits 0 | 18 of 18, and 427 tests in 9 classes, 0 failures |

The patch is 34 lines added and 10 removed in `HttpConn.java`:
`new Socket(Proxy.NO_PROXY)`; an `SSLContext.getInstance("TLS")`
initialised with the JVM's default trust managers, per connection, in
place of `SSLSocketFactory.getDefault()`; `Transfer-Encoding` exactly
`chunked`, once; `Content-Length` digits only, once; no whitespace
before a colon or at a line's start; and no message with both. One
consequence to accept or answer: with its own context the engine follows
`javax.net.ssl.trustStore` (and cacerts) but no longer a trust that other
code installs with `SSLContext.setDefault`; the ported test's `JvmTrust`
now sets the trust store property as well. A caller who trusts a private
CA only programmatically would need a `ServerSource.url` overload that
takes it. The patch's cost per request (a header loop check and a regex
per length) was not timed.

Read but not run: `Target` drops an IPv6 literal's brackets
(`ServerSources.target`), so `main`'s `HttpConn` writes `Host: ::1:8080`
for `http://[::1]:8080`, which RFC 9112 does not allow; this host has no
IPv6 to try it on. Fixed on PR #222 in f1bbeff, where `HttpConnTest`
checks the header text. Still open there: `exactly(n)` allocates the
declared length (up to 64 MiB) before the first body byte arrives.

## 3. A stdio transport, and one process per call

`TransportBench.java` on the same binary, two rounds per JVM
(`results/bench-round1.txt`, `results/bench-round2.txt`). The g5 receipt
(7,556 bytes as base64); p50 in µs, the two rounds.

| Path | JDK 21 | Temurin 8 |
|---|---|---|
| Managed child, `HttpConn` keep-alive, g5 | 2,156 / 2,505 | 2,238 / 2,283 |
| Managed child, `GET /healthz` (transport alone) | 63.4 / 51.6 | 52.3 / 54.7 |
| Frame through a pipe and back (`cat`), 2 bytes | 24.5 / 26.5 | 26.1 / 27.9 |
| Frame through a pipe and back, 7,556 bytes | 29.7 / 32.4 | 31.9 / 30.2 |
| One `aprv verify-receipt` process per call, g5 | 15,981 / 16,583 | 14,649 / 15,695 |

One process per call averaged 17.4 to 26.3 ms with a p99 of 25 to 157 ms
(round 1 had outliers on both JVMs). Its answer was byte-identical to the
server's in all four runs. It was measured without the SHA-256 check that
`ServerProcess` makes of the binary before every start; per call, that
would hash 12 MB each time.

**What stdio could save:** the transport's share. A loopback HTTP
exchange with no work behind it costs 52 to 63 µs, a pipe round trip 25
to 32 µs, so the ceiling is about 30 µs a call, 1 to 2% of a g5
verification.

**What it would cost.** `aprv serve --managed` would read length-prefixed
frames on stdin and write them on stdout (stderr stays the log), keeping
stdin's EOF as the parent's death signal. The engine runs calls on
several threads in parallel today (a connection pool, one request per
connection; the server's `workers` permits). Over one pipe pair that
needs a request id in each frame, a reader thread and a table of pending
calls in Java, and a writer lock and a worker pool in Rust: a small RPC
protocol, with its own status codes standing in for the HTTP routes'
statuses and problem documents (`openapi.yaml`), its own tests and its
own fuzzing. The alternatives are one child per concurrent call (about
20 MiB resident each, 10 ms to start, by the
[static musl note][musl]) or one call at a time (the 4-thread rate
falls to the 1-thread rate). The estimate: 120 to 180 lines of Rust and
about 200 lines of Java plus tests, against a handshake that loses the
token and the port line.

`ServerSource.url` still needs HTTP, so the engine would carry two
transports for one job (send a request, read the module's answer) unless
`url` were dropped. What stdio gains on top of the patched `HttpConn`:
no loopback port, which another local process can connect to but must
present a 256-bit token on, and no HTTP parsing on the managed path. The
proxy and TLS rows of section 1 do not apply to a managed child after the
patch either (loopback, `NO_PROXY`, plain http).

**One process per call** needs no new protocol: it is the CLI PHP's
`CliTransport` already uses, and it would retire the port, the token, the
handshake and the restart supervision. It costs 13 to 14 ms a call more
than the managed child, and more again with the per-start hash, so it
fits a host that verifies a few receipts a minute, not a batch.

## 4. The rest of the field

| Client | Last release (Central) | Java floor | Added to the classpath | Advisories (OSV) | Verdict |
|---|---|---|---|---|---|
| Apache HttpClient 5.6.4 classic | 5.6.4; 5.7-alpha1 2026-08 | 8 | httpclient5 1,057,058 + httpcore5 955,121 + httpcore5-h2 263,675 + slf4j-api 41,125 = 2,316,979 bytes; zstd-jni, brotli4j, Commons Compress, Conscrypt optional | CVE-2025-27820 (5.4.0–5.4.2: host name verification off), CVE-2026-40542 (5.6.0), CVE-2026-64607 (before 5.6.3), CVE-2026-54399 (httpcore5 before 5.4.3: header memory exhaustion) | the one library that meets the bar once configured; see below |
| Apache HttpClient 4.5.14 | 2022-12-04 (no release since) | 6 | httpclient 785,639 + httpcore 327,891 + commons-logging 61,829 + commons-codec 335,042 = 1,510,401 | CVE-2020-13956, older | stale line; same JVM-wide proxy and logging questions; out |
| OkHttp 4.12.0 / 5.5.0 | 5.5.0, 2026-08 | 8 | okhttp-jvm 961,167 + okio-jvm 392,463 + kotlin-stdlib 1,724,058 = 3,077,688 (5.5.0) | CVE-2021-0341, CVE-2016-2402 (both certificate checks) | Kotlin stdlib and Okio on every Java 8 classpath, a version Spring Boot also manages (`kotlin.version`); default `ProxySelector` and retries (from its documentation, not probed); out |
| Jetty client 9.4.58 | 2025-08 | 8 | jetty-client 331,809 plus jetty-http, -io, -util | none listed for jetty-client | 9.4 is past Eclipse community support; 12.x needs Java 17; out |
| Jodd HTTP 6.3.0 | 2022-08 | 8 | 85,474 plus jodd-util | CVE-2022-29631 (SSRF) | inactive since 2022; out |
| Methanol 1.9.0 | 2025-12 | 11 | 571,035 on `java.net.http` | none listed | Java 11+, and inherits `java.net.http`'s property; out |
| `java.net.http` | the JDK | 11 | none | the JDK's | no Java 8, and section 1's host name property; out |
| `HttpURLConnection` (PR #222) | the JDK | 8 | none | the JDK's | the Java 8 `Authenticator` residual and resends ([HttpURLConnection][huc]); out |

**Spring Boot and HttpClient 5.** Boot's dependency management pins
httpclient5 and httpcore5 for every app that uses it: 5.1.4 and 5.1.5 in
Boot 2.7.18 (the last Java 8 line), 5.5.2 and 5.3.6 in 3.5.16, 5.5.1 and
5.3.6 in 4.0.0, 5.6.4 and 5.4.3 in 4.1.1 (`spring-boot-dependencies`
POMs on Central). The engine's audience on the server engine is Java 8,
so the likely host is Boot 2.7, where 5.1.4 has neither `ConnectionConfig`
(5.2) nor `DetachedSocketFactory` (5.4) and a client built against 5.6
fails with `NoClassDefFoundError`. On Boot 3.5 the managed versions are
inside the ranges of CVE-2026-64607 and CVE-2026-54399. Only shading
(relocating HttpClient 5 into this jar) avoids both, and a shaded copy is
a private fork: each HttpClient 5 advisory becomes a release of this
artifact, against Maven Central's budget of five a month (CLAUDE.md).

## 5. Java 11+ on `java.net.http`, Java 8 on `HttpConn`

Two clients for one job, each with its own tests, and the Java 11 one
carries section 1's host name property. Java 11 and later run Endive by
default; the server engine there is an explicit choice, so the second
client would serve the minority path. Out.

## Verdict

1. **Keep `HttpConn`, apply `httpconn-hardening.patch`, and take the
   ported tests.** After the patch it refuses every case in section 1
   that any library refuses, reads no JVM-wide proxy, TLS context,
   `Authenticator` or logging setting, never resends inside an attempt,
   and passes PR #222's tests unchanged in substance. It is the only
   option with no global state left to document as a residual. The code
   it keeps is 305 lines that do one job against one server whose wire
   contract this repository writes.
2. **HttpClient 5.6, shaded**, if the owner prefers a library to those
   lines: strict parsing for free, but about 120 to 150 lines of
   configuration and checks around it (framing, cap, cancel on refusal,
   `NO_PROXY` through `@Internal` API), 2.3 MB of shaded classes, its
   SLF4J logging (which `-D` flags turn on, token and receipt included),
   and its advisories as this artifact's releases.

Not recommended: a stdio transport (about 30 µs a call, a second protocol
in two languages, and HTTP still needed for `url`); one process per call
as the default (about 7 times slower per call); `HttpURLConnection`,
`java.net.http`, the hybrid, and the stale or Kotlin-based clients.

## Where this stops holding

- One Linux machine, loopback, shared CPUs, two rounds; a `url` source
  across a real network was not measured. The 5.6 s drip row depends
  only on the timeouts chosen.
- Section 1's library behaviour is what these versions do: HttpClient
  5.6.4 with HttpCore 5.4.3, JDK 21.0.10, Temurin 8u504. JDKs 11 to 20
  and 22 to 27 were not run here.
- OkHttp, Jetty and Jodd were judged from their POMs, release dates and
  OSV records, not probed.
- Only `Basic` challenges and SLF4J's simple binding were tried; NTLM,
  Negotiate and other logging back ends were not.
- The shaded jar's size, with or without minimising, was not measured.

[huc]: 2026-10-02-java-httpurlconnection.md
[musl]: 2026-09-27-static-musl-server.md
