# The surface: the 0.7 API, unchanged

Status: **accepted**, rewritten on 2026-09-28. The owner's rule from
2026-09-25 still stands:

> The binding generator must never become the architecture.

Since the Wasm-first basis (DECISIONS.md R22) there is no generator at
all. The surface is the public API that 0.7.0 already ships in nine
languages, specified in [docs/design/0.7-api.md][api07] and implemented
for reference in `java/src/main/java/.../{Config,Verifier,DefaultVerifier,Reason}.java`.
0.8.0 changes what sits under that API, not the API. This file says what
the surface is, where each part lives in the Rust crates, and how CI
proves every host keeps it.

## 1. Three layers, one direction

```text
wrappers            Java (-wasm), JS, Go, Python, Swift, Ruby, .NET, PHP;
                    rust/ffi (C ABI); aprv-server
      │  own loading, pooling, idiom, the clock read; no policy, no parsing
      ▼
aprv-abi / aprv-wire   the canonical-ABI exports (WIT); the 0.7 canonical JSON bytes
      ▼
aprv-surface        the 0.7 model: operations, Reason, payloads, Failure, roots
      │  depends on the core only; no generator, no runtime, no wire format
      ▼
aprv-core           every security decision
```

- **The core** parses, verifies and decides.
- **The surface** names the 0.7 concepts once, in plain Rust, with checked
  conversions. It holds no crypto, no parsing, no policy.
- **The wire** writes the surface's values as the JSON that 0.7 defines,
  and reads `init`'s configuration.
- **Wrappers** present the API in one language: names, idiomatic types,
  the clock read, instance pooling, trap recovery. Nothing else.

Reviewing security means reviewing the core. Reviewing a wrapper is
mechanical: read the clock, move bytes in, move JSON out, map the
outcome.

## 2. Setup and the three operations

As in [0.7-api.md][api07], "Setup":

```java
Config.defaults()                       // the three pinned Apple roots + Clock.systemUTC()
Config.builder().roots(...).clock(...).build()
Verifier.create(config)                 // throws at startup, never later
  VerificationResult<ReceiptPayload> verifyReceipt(String base64)
  VerificationResult<JsonPayload>    verifySignedData(String jws)
  String                             verifyReceiptEndpoint(Environment env, String requestJson)
```

Each language spells these in its own idiom; the 0.7 table of ports
("The other ports") gives the result form, clock type, data types and id
type of each, and 0.8.0 keeps every row.

- **No policy parameter.** No bundle id, environment filter, app Apple id
  or device id. The environment of `verifyReceiptEndpoint` is which of
  Apple's two URLs the call imitates.
- **No per-call time.** The `Config` clock is read once per call by the
  wrapper and crosses the ABI as `now-ms` (ARCHITECTURE.md §6). The ABI
  carries `now-ms` per call, so a public override later is additive
  (DECISIONS.md R24).
- **Startup failures** stay where 0.7 puts them: an empty root set is
  refused by `Verifier.create`; bundled roots that do not parse fail
  `Config.defaults()`. A Wasm host adds two of its own at `create`: an ABI
  mismatch, and a root `init` refuses.
- **The verify methods never throw for any input.** A null or empty input
  string is `MALFORMED`; a null `Config` or `Environment` is the
  language's programmer error. A trap or a server failure is
  `INTERNAL_ERROR` (21009 at the endpoint), with the category kept in the
  cause (ARCHITECTURE.md §4).
- **`Config` is exactly 0.7's** in every package, the Java `-wasm`
  artifact included. The engine of that artifact is a second argument to
  `Verifier.create`, never a `Config` field (DECISIONS.md R25).

## 3. The eight reasons

`MALFORMED`, `TOO_LARGE`, `INVALID_SIGNATURE`, `UNTRUSTED_CHAIN`,
`INVALID_CERTIFICATE`, `INVALID_CERTIFICATE_PURPOSE`, `UNREADABLE_PAYLOAD`
and `INTERNAL_ERROR`. Their meanings, the rule for which failure a parse
problem gets, and the endpoint's status table (0, 21002, 21003, 21007,
21008, 21009) are in [0.7-api.md][api07], "Result" and §3. `Reason.java`
carries the same text as Javadoc. No new reason is added in 0.8.0; a
revoked certificate, if revocation ever lands, is `INVALID_CERTIFICATE`.

## 4. Payloads and the canonical JSON

[0.7-api.md][api07] §1 defines `ReceiptPayload` and `InAppPurchase`, their
decode rules, and "Our JSON"; §2 defines `JsonPayload`, whose `json()` is
the verified payload exactly as signed. What the Wasm hosts depend on:

- `ReceiptPayload.toJson()` is **the same value, not the same bytes**:
  valid UTF-8 JSON whose parsed value equals the one the rules define.
  aprv-wire writes one fixed byte form; a wrapper may hand it through or
  re-encode it with its language's encoder.
- 64-bit ids are JSON strings; dates are epoch-millisecond numbers; bytes
  are padded standard base64; a missing field is `null`; unknown
  attributes are an object keyed by the decimal type, values in receipt
  order.
- `JsonPayload` crosses the ABI as a JSON string holding the signed
  payload's bytes, so no host re-serialises Apple's claims.
- The endpoint's answer crosses as Apple's response JSON, byte for byte.

## 5. The bounds

Every bound in [0.7-api.md][api07], "Bounds", is owned by the core and
none is configurable: the receipt's base64 and the endpoint body at
3,145,728 UTF-8 bytes, the JWS at 262,144, ASN.1 nesting 32, 10
embedded certificates, six certificates below the anchor, 4 SignerInfos.
JSON has no bound of its own in the core since 2026-10-01: a value nobody
reads is skipped, not built, within the size caps (DECISIONS.md R40);
Java keeps its three JSON bounds. Wrappers add none. `aprv-server` adds one transport rule: an HTTP body
over 3,145,728 bytes is refused with 413 before it reaches the module, as
Apple's endpoint refuses it ([aprv-server §1][server]).

## 6. The contract: `fixtures/cases.json` schema v2

- 311 cases, validated by `fixtures/cases.schema.json`: 136
  `verifyReceipt`, 99 `verifySignedData`, 43 `verifyReceiptEndpoint` and
  33 `decodeBase64` (counted from the file on 2026-09-28).
- A case's `config.trustedRoots` is either the defaults or registered
  trust-anchor fixtures; its `config.now`, when present, is the instant
  the `Config` clock answers. A Wasm host expresses both through the
  public API: the roots go into `Config` and so into `init`, and the
  clock becomes `now-ms`. The ABI v1 spike's test-only operations (op +
  256, anchors and a pinned clock in the envelope) are therefore not part
  of the ABI ([ABI v1][abi], open questions; [canonical ABI][cabi]).
- A `oneOf` case lists the outcomes a port may give, at the endpoint the
  `/status` values; `INTERNAL_ERROR` is never among them, and no exception
  or panic may escape. 42 cases carry
  `maxMillis` 2,000, measured after one warm-up call of the same case.
- `decodeBase64` cases call the `receipt-data` and `x5c` decoders
  directly. In the core they run as today. Through a host, a
  `receipt-data` text runs through VERIFY_RECEIPT and must land on its
  group's side of the rule, as all 167 texts did through op 1 in the ABI
  spike ([ABI v1][abi]); an `x5c` text needs a JWS whose header carries
  it, which Phase 1 builds for the runners.

## 7. Enforcement

- **Every host runs all 311 cases, as one test each,** as every port does
  today. A runner also asserts that every case id in the file ran.
- **The Java `-wasm` artifact runs them once per engine:** Endive, and the
  server engine (on Temurin 8 in the `java-runtime-8` leg, and on a
  current JDK).
- **The main Java artifact runs them** as it does today; with the core
  running them too, a case both pass is where the two implementations
  agree (DECISIONS.md R33).
- **The C ABI** runs them through its C++ and ctypes harnesses, and
  `aprv-server` through its HTTP routes and its CLI.
- **ABI tests.** The ABI tests of the canonical-ABI final round, plus
  each facade's own, run on every host ([canonical ABI final][cabifinal];
  ARCHITECTURE.md §9).
- **Reason parity.** Each wrapper's test lists its reason names and
  compares them with the surface's eight.
- **The corpus** (1,179 rows plus 5,000 mutants) runs on every change
  through a trap-on-anything host and through the built Endive jar, byte
  for byte against native (ARCHITECTURE.md §9).

## 8. How the crates map onto the surface

| 0.7 concept (Java spelling) | `aprv-surface` | `aprv-wire` / the WIT |
|---|---|---|
| `Config.roots()` | `Vec<Vec<u8>>` of roots, each DER or PEM (the core tells them apart), empty = the three compiled-in Apple roots | `init(config-json: list<u8>)`: `{"roots":["<base64 DER or PEM>", ...]}` |
| `Config.clock()` | not modelled: the wrapper reads it | `now-ms: u64`, the first argument of each verify export |
| `verifyReceipt(base64)` | `verify_receipt(&[u8], now_ms)` | `verify-receipt(now-ms, receipt-base64: list<u8>)` |
| `verifySignedData(jws)` | `verify_signed_data(&[u8], now_ms)` | `verify-signed-data(now-ms, jws: list<u8>)` |
| `verifyReceiptEndpoint(env, body)` | `verify_receipt_endpoint(Environment, &[u8], now_ms)` | `verify-receipt-endpoint(env: u32, now-ms, request-json: list<u8>)` |
| `Environment` (2) | `Environment` (2) | `env`: 0 production, 1 sandbox; anything else traps |
| `Reason` (8) | `Reason` (8), with `token()` | `"reason":"<TOKEN>"` |
| `Failure` (reason, message, cause) | `Failure { reason, message }` | `{"verified":false,"reason":...,"message":...}` |
| `ReceiptPayload`, `InAppPurchase` | records of `Option<String>`, `Option<i64>`, `Option<bool>`, `Vec<u8>`, lists; unknown attributes as `(i64, Vec<Vec<u8>>)` in receipt order | 0.7's "Our JSON" |
| `JsonPayload.json()` | `String`, the signed bytes | a JSON string |
| `VerificationResult<T>` | `Result<T, Failure>` | `{"verified":true,"payload":...}` or the failure |

Conversion rules carried over from the 2026-09-25 surface audit:

- No unsigned integers on the surface; ids are `i64`, since a hostile
  ASN.1 INTEGER can be negative ([0.7-api.md][api07], the other ports).
- `TryFrom` wherever a value can fail to fit, `From` only when it is
  total; `clippy::cast_*` denied. A conversion failure becomes
  `INTERNAL_ERROR` and never a success.
- The core's `cause` chain is Rust-only; the wire carries the message.

## 9. Layering, checked

`tools/check-layering.mjs` reads `cargo metadata` for the workspace and
fails when:

1. the core's graph contains a binding-generator or Wasm-runtime crate
   (`wasm-bindgen*`, `js-sys`, `pyo3*`, `jni*`, `napi*`, `wasmtime*`,
   `wit-bindgen*`, `cbindgen`, `serde_derive`, and the generators of
   DECISIONS.md's rejected table); `wit-bindgen` belongs to `aprv-abi`
   alone;
2. the surface's graph contains anything outside the core's, or
   `serde`/`serde_json`;
3. a boundary crate (`aprv-abi`, `rust/ffi`) reaches the core except
   through the surface and the wire;
4. `unsafe` appears outside `aprv-openssl`, `aprv-abi`, `rust/ffi` and
   `aprv-server`, or a crate that must carry `#![forbid(unsafe_code)]`
   lacks it;
5. the core has a module named `asn1`, `x509`, `cms`, `chain` or
   `crypto`, or an ASN.1, X.509 or signature crate in its graph (R21).

cargo-deny adds a second guard on rule 1. The C ABI keeps its
`catch_unwind` source test and gains `deny(improper_ctypes,
unsafe_op_in_unsafe_fn, ffi_unwind_calls)`, Clippy's
`undocumented_unsafe_blocks`, and an exported-symbol allowlist.

## 10. What stays in the core, whatever a wrapper wants

Certificate-chain verification, root selection and pinning, Apple's
marker OIDs, signature algorithms, receipt parsing, strict base64, JWS
parsing and validation, signed-date and validity-window policy, input
caps, JSON reading rules, unknown-attribute handling, the verifyReceipt status
mapping (21007, 21008), and the reason vocabulary. A wrapper that
implements any of these has failed the architecture, even when its output
agrees. The one exception by design is the Java implementation, which is
a second implementation, not a wrapper (DECISIONS.md R33).

[api07]: ../design/0.7-api.md
[abi]: ../evidence/2026-09-26-wasm-abi-v1.md
[cabi]: ../evidence/2026-09-29-canonical-abi-spike.md
[cabifinal]: ../evidence/2026-09-29-canonical-abi-final.md
[server]: ../evidence/2026-09-26-aprv-server.md
