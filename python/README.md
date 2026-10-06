# apple-purchase-receipt-verifier

Verify Apple in-app purchases locally — no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS transactions and legacy PKCS#7 receipts against pinned Apple
root certificates.

```bash
pip install apple-purchase-receipt-verifier
```

The import package is `apple_purchase_receipt_verifier`; the distribution is
`apple-purchase-receipt-verifier`. Requires Python 3.10+.

## Before you deploy

The verification core is one WebAssembly module, `aprv.wasm`, that this package
runs on [wasmtime-py](https://pypi.org/project/wasmtime/). The Python code moves
bytes in and out and parses nothing. In a source checkout the module is not
committed: copy it into `apple_purchase_receipt_verifier/`. The package loads only that file, checked against
`aprv.wasm.sha256`, and reads no variable to pick another.

- **It compiles at start.** The first `Verifier` in a process compiles the
  module: 1 to 3 s on an idle machine, up to 8 s on a busy shared one (about
  5 s of CPU). A later one in the same process takes about 3 ms. Build the
  `Verifier` at start-up, never per request.
- **A compile cache is on by default** and brings a start to about 0.1 s
  (54 MB resident, against 150 MB for a compile). It
  lives in your own user cache directory; `APRV_WASM_CACHE_DIR` moves it, and
  an empty value turns it off ([the rules](#the-compile-cache)).
- **AWS Lambda pays the compile in every new container**, about 3 s or more on
  one vCPU: the package directory is read-only and nothing survives a cold start.
  Create the `Verifier` in the init phase, outside the handler, and count it in
  your cold-start budget.
- **Use worker processes, not threads.** A `Verifier` is thread-safe, but
  wasmtime-py scales threads badly: on an idle 4-CPU machine, 583, 946 and 566
  receipts per second at 1, 2 and 4 threads, against 595, 1,123 and 2,259 with
  processes (an idle machine and an earlier build of the module; the shape
  comes from wasmtime-py, not from the module). With gunicorn or uvicorn, one
  `Verifier` per worker.
- **Platforms follow wasmtime-py's wheels:** Linux (glibc and musl), macOS and
  Windows, on x86_64 and arm64. Elsewhere (32-bit machines, ppc64le, s390x,
  riscv64) `pip install` stops with a pointer to `aprv-server`, a standalone
  binary or Docker image any language can call, or to the C ABI, instead of
  installing a package whose import fails.

## Quick start

One `Verifier`, built from a `Config`, exposes the three entry points. It is
immutable and thread-safe once constructed, and none of its `verify_*`
methods raise: each returns a `VerificationResult` (or, for the endpoint, a
JSON string) that reports failure instead of throwing.

```python
from apple_purchase_receipt_verifier import Config, Environment, Verifier

verifier = Verifier(Config())  # Apple's three pinned roots, system clock
```

**StoreKit 2 signed transaction or renewal info (compact JWS):**

```python
result = verifier.verify_signed_data(jws)
if not result.verified:
    raise ValueError(f"{result.failure.reason}: {result.failure.message}")
payload = json.loads(result.payload.json)  # the verified claims, as a dict
```

**Legacy PKCS#7 app receipt (base64):**

```python
result = verifier.verify_receipt(receipt_b64)
if not result.verified:
    raise ValueError(f"{result.failure.reason}: {result.failure.message}")
receipt = result.payload  # a ReceiptPayload
print(receipt.bundle_id, len(receipt.in_app))
```

**A `verifyReceipt`-shaped request body, verified offline:**

```python
response_json = verifier.verify_receipt_endpoint(Environment.PRODUCTION, request_body)
```

`request_body` is the raw JSON body Apple's endpoint would have received
(`{"receipt-data": "...", "password": "..."}`); `response_json` is the JSON
string Apple's endpoint would have answered, `status` field included. See
"The verifyReceipt-compatible endpoint" below for the raw-body caveat and the
status table.

### Your own roots

`Config(roots=[...])` takes certificates as `bytes`, DER or PEM (the
bytes of a `.cer` or a `.pem` file), for tests and for anyone who pins
something other than Apple's roots. The module tells the two apart by the
bytes; a PEM file holding several certificates is one entry, and every
certificate in it is trusted. The module parses them when the `Verifier` is
built, so a value that is not a certificate is a `ValueError` there, never a
later verdict.

Apple's three roots are compiled into the module, and the package carries no
copy of them: `Config().roots` is `None`, which the `Verifier` hands
the module as `{}`, meaning those three. To trust Apple's roots and one
of your own, pass all of them, reading Apple's from its PKI page or the
repository's `certs/`:

```python
from pathlib import Path

from apple_purchase_receipt_verifier import Config, Verifier

apple = [path.read_bytes() for path in sorted(Path("certs").glob("*.cer"))]
verifier = Verifier(Config(roots=[*apple, Path("my-test-root.cer").read_bytes()]))
```

`Verifier` fails at construction, never later, for an empty root set (an
explicitly empty collection, not `None`), a root the
module refuses, or a module it cannot run (an ABI mismatch is a `RuntimeError`
naming the version expected). The `verify_*` methods never raise. A trap inside
the module, an answer the wrapper cannot read, and a `Config.clock` that
raises or answers anything but epoch milliseconds are all
`Reason.INTERNAL_ERROR` (status 21009 at the endpoint); the instance involved
is discarded and the next call uses a fresh one.

### The compile cache

Wasmtime writes the compiled module to disk, so the next process loads it
(about 0.1 s warm, against 1 to 3 s to compile on an idle machine and about 5 s
of CPU on a busy one; `docs/evidence/2026-09-29-python-g1.md`). The cache holds native
code that the next process runs, so anyone who can write its directory can plant
code. The rules:

1. The default is your own user cache directory, as
   [platformdirs](https://pypi.org/project/platformdirs/) names it:
   `~/.cache/apple-purchase-receipt-verifier/wasmtime` on Linux,
   `~/Library/Caches/apple-purchase-receipt-verifier/wasmtime` on macOS (on
   both, under `$XDG_CACHE_HOME` when that is an absolute path), and
   `%LOCALAPPDATA%\apple-purchase-receipt-verifier\wasmtime` on Windows. It is
   created private (mode 0700). An empty `HOME` counts as unset, and the
   home directory then comes from the password database. With no home
   directory, a relative `HOME`, or any other failure to name the directory,
   the cache is off.
2. `APRV_WASM_CACHE_DIR` names another absolute path. Set it empty for no cache.
3. The cache is off, silently, when the directory is read-only or cannot be
   created, is not owned by you, or is writable by group or others, or when
   its parent is one someone else could swap. A shared directory such as `/tmp`
   never holds it. Off is not an error: the process compiles at start and
   verifies as usual.
4. On Windows there are no owner or mode bits to read, so only the read-only
   rule applies.

A `Verifier` made before a `fork` keeps answering in the children, and one made
after it reuses the process's compiled module.

## Integrating: from verified payload to entitlement

Verification proves Apple signed the bytes. It does not prove the presenter
owns them, and it says nothing about what happened after the signature. The
[project README](../README.md#integrating-from-verified-payload-to-entitlement)
lays out the full flow once, with a reason-to-next-step table; here are its
two branches in this port's 0.7 API.

Both branches now follow the same shape: verify, deny on any failure, then
run the [post-verification checklist](#post-verification-checklist) below
yourself: 0.7 has no constructor-supplied bundle id or environment allowlist
to do it for you.

```python
# Branch A: StoreKit 2 signed transaction
result = verifier.verify_signed_data(jws)
if not result.verified:
    log(result.failure.reason)  # deny; nothing partial is returned
    return
payload = json.loads(result.payload.json)
if payload.get("bundleId") != "com.example.app":
    return  # step 1 of the checklist below
environment = result.payload.environment  # Environment.PRODUCTION, .SANDBOX or None
if payload.get("revocationDate") is not None:
    return  # refunded or revoked as of signing time
expires = payload.get("expiresDate")
if expires is not None and expires <= now_ms:
    return  # subscription term had ended
grant(payload["productId"], environment, payload["transactionId"])  # idempotent on transactionId

# Branch B: legacy PKCS#7 app receipt
result = verifier.verify_receipt(receipt_b64)
if not result.verified:
    log(result.failure.reason)
    return
receipt = result.payload
if receipt.bundle_id != "com.example.app":
    return
environment = receipt.environment
for purchase in receipt.in_app:
    if purchase.cancellation_date_ms is not None:
        continue
    if purchase.expires_date_ms is not None and purchase.expires_date_ms <= now_ms:
        continue
    grant(purchase.product_id, environment, purchase.transaction_id)
```

**Freshness is your call.** Neither method rejects a payload for its age;
the signing instant (`signedDate` / the receipt's creation date) only
decides what certificate-validity window the chain is judged against. The
right freshness limit depends on the endpoint (Apple retries a server
notification for days, and a device may legitimately present an old but
genuine receipt), so apply one yourself where it fits.

## Post-verification checklist

A verified payload is only proof of what Apple signed. Nothing here checks
whether it applies to *your* app or has already been used. Every caller does
these four things with the signed fields before granting anything:

1. **Bundle id.** Compare it against your app's bundle id yourself.
   Legacy: `receipt.bundle_id`. JWS: `payload["bundleId"]`.
2. **Environment.** `receipt.environment` for a legacy receipt and
   `result.payload.environment` for a JWS payload, as the module states it.
   A receipt's comes from `receipt_type` (`Production` and `ProductionVPP`
   are `PRODUCTION`, `ProductionSandbox` and `ProductionVPPSandbox`
   `SANDBOX`); a JWS's from the first of the top-level `environment` claim,
   a notification's `data.environment` and a summary notification's
   `summary.environment` that is present. Decide whether you accept
   `SANDBOX` here; it is `None` for a value that names neither (`Xcode`,
   `LocalTesting`) or none, which fails closed if you require a specific
   `Environment`. It is not part of `to_json()`.
3. **Product id.** Compare `product_id` / `payload["productId"]` against
   the catalogue of products you actually sell: a signature proves Apple
   signed it, not that it's a product your server still grants.
4. **Idempotency.** Key your own bookkeeping on the transaction id
   (`transaction_id` / `payload["transactionId"]`) so a replayed or retried
   JWS/receipt is not granted twice.

None of this is checked by `verify_receipt`, `verify_signed_data` or
`verify_receipt_endpoint` themselves: 0.7 dropped constructor-supplied
policy (bundle id, allowed environments) entirely; every check above is read
off the returned payload by the caller, every time.

## Device hash

Legacy receipts carry a device-binding hash (attribute 5,
`ReceiptPayload.sha1_hash`) that Apple's on-device code computes as
`SHA-1(device_id + opaque_value + bundle_id_bytes)`. The library does not
call this check itself: the design (0.7) treats it as a caller decision,
since `device_id` is something only the caller has (the app supplies its own
device identifier bytes; there is no single canonical source across
platforms). `device_hash` computes the formula for you:

```python
from apple_purchase_receipt_verifier.receipt import device_hash

expected = device_hash(device_id_bytes, receipt.opaque_value, receipt.bundle_id_bytes)
if expected != receipt.sha1_hash:
    raise ValueError("receipt was not issued for this device")
```

`opaque_value` and `bundle_id_bytes` are the raw attribute value octets, not
the decoded strings, because the hash is defined over the DER bytes Apple
signed.

## App Store Server Notifications V2

A V2 notification body is itself a compact JWS whose decoded payload carries
further compact JWS strings nested inside it (`data.signedTransactionInfo`,
`data.signedRenewalInfo`). Verify the outer envelope, then verify each
nested one the same way:

```python
import json

outer = verifier.verify_signed_data(request_body)
if not outer.verified:
    raise ValueError(f"{outer.failure.reason}: {outer.failure.message}")
notification = json.loads(outer.payload.json)

data = notification.get("data", {})
for key in ("signedTransactionInfo", "signedRenewalInfo"):
    nested_jws = data.get(key)
    if nested_jws is None:
        continue
    nested = verifier.verify_signed_data(nested_jws)
    if not nested.verified:
        raise ValueError(f"{key}: {nested.failure.reason}: {nested.failure.message}")
    # json.loads(nested.payload.json) is the transaction or renewal info:
    # run the post-verification checklist above on it before acting.
```

Each nested JWS is checked against the same pinned roots as the outer one;
there is nothing notification-specific about `verify_signed_data` itself.

## The verifyReceipt-compatible endpoint

`verify_receipt_endpoint` is a stateless, one-shot replacement for Apple's
deprecated endpoint: same request body, same response body, same status
codes, verified offline against the pinned roots instead of by calling
Apple. It never raises. Fields that only Apple's own server-side database
can supply (`latest_receipt_info`, `pending_renewal_info`) are not produced.
Like Apple's own endpoint, it checks no bundle id: compare
`json.loads(response)["receipt"]["bundle_id"]` yourself.

| status | meaning |
|---|---|
| 0 | Valid. `environment` and `receipt` are present in the response. |
| 21002 | `receipt-data` is missing, not a string, too large, or the body isn't valid JSON. |
| 21003 | The receipt failed to authenticate (bad signature, untrusted chain, expired or wrong-purpose certificate). |
| 21007 | A sandbox receipt was sent to `Environment.PRODUCTION`. |
| 21008 | A production receipt was sent to `Environment.SANDBOX`. |
| 21009 | Internal data access error: the receipt authenticated but its signed content does not parse, or the library itself failed. Deterministic; alert, don't retry. |

No other `verifyReceipt` status (21000, 21001, 21004, 21005, 21006, 21010,
21100-21199) is ever returned: those describe HTTP-method, shared-secret and
Apple-server-side conditions this offline replacement cannot produce. See
`apple_status` for the named constants behind each code.

**Read the raw body.** A web framework that parses
`application/x-www-form-urlencoded` bodies rebuilds the request from parsed
fields, which is not byte-for-byte the JSON Apple's endpoint contract
expects. Read the raw request body and pass it straight through:

```python
@app.post("/verifyReceipt")
async def handle_verify_receipt(request: Request) -> Response:
    raw_body = (await request.body()).decode("utf-8")
    response_json = verifier.verify_receipt_endpoint(Environment.PRODUCTION, raw_body)
    return Response(response_json, media_type="application/json")
```

## Decode rules

Reading a legacy receipt's attributes follows a few fixed rules, the same in
every port:

- **First occurrence wins.** If Apple's payload repeats an attribute type
  (it shouldn't, but the parser doesn't assume that), the first occurrence
  decides the field; later copies are kept raw in `unknown_attributes`.
  This applies to the receipt creation date too, since it anchors the
  certificate-validity check.
- **Dates** are RFC 3339 `date-time` strings: `T` and `Z` in either case, a
  fraction truncated to the millisecond, `Z` or an offset `±hh:mm` converted
  to UTC. Anything else leaves the field `None` rather than raising, and a
  non-empty string that does not parse is kept raw. An empty date string
  means "not set". Decoded dates are epoch milliseconds, UTC.
- **Strings** are `UTF8String` or `IA5String` only; `IA5String` bytes ≥ 0x80
  fail to decode (7-bit ASCII, by definition). A string that fails to decode
  leaves the field `None` (or, for `bundle_id`, only `bundle_id_bytes` is
  set, see below) rather than raising.
- **`unknown_attributes`** holds the raw value octets of every attribute
  that does not end up in a named field, keyed by attribute type, in
  receipt order: a type the payload doesn't model, a later copy of a known
  one, and a known one whose value does not parse. A field Apple adds later
  is never silently dropped. `bundle_id` (attribute 2) is the one exception: a decode failure there
  does not also appear in `unknown_attributes`, because `bundle_id_bytes`
  already carries the raw value unconditionally.
- **64-bit ids** (`app_item_id`, `download_id`, `version_external_identifier`,
  `web_order_line_item_id`) are plain Python `int`; `ReceiptPayload.to_json()`
  renders them as JSON strings (JSON numbers lose precision above 2^53) and
  everything else as JSON numbers, the same value every other port
  writes (the bytes may differ).

## Upgrading from 0.7

The API is the 0.7 API, with one way to build a `Config`. What changed
otherwise is what sits under it.

- **`Config(...)` is the one way to build a `Config`.** `Config.create(roots=...,
  clock=...)` becomes `Config(roots=..., clock=...)`, and `Config.defaults()`
  becomes `Config()`. The constructor takes any iterable of roots, and `None`
  for either argument means its default, as `create` did.
- **Roots are DER or PEM `bytes`, not `cryptography` certificates.**
  `Config(roots=[cert.public_bytes(Encoding.DER)])` for a
  `cryptography.x509.Certificate`. Anything else is a `TypeError`.
- **`default_roots()` is gone, and `Config().roots` is `None`.**
  Apple's three roots are compiled into the module, which trusts them when no
  roots are given; the package no longer ships a copy to return.
- **The dependencies are `wasmtime` and `platformdirs`.** `cryptography` and
  `asn1crypto` are no longer installed by this package; `platformdirs` names
  the compile cache's directory.
- **The first `Verifier` compiles a module** (see the top of this file).
- **`Failure.cause` is set only for an `INTERNAL_ERROR` this package raised**
  (a trap, a failing clock). It is `None` for `UNREADABLE_PAYLOAD`: the message
  says what did not parse.
- **The module-private helpers are gone** (`_receipt_base64`,
  `verify_receipt_der`, and the rest of the hand-written verifier).
  `receipt.device_hash`, `receipt.MAX_EMBEDDED_CERTIFICATES` and
  `receipt.MAX_SIGNER_INFOS` stay.
- **`receipt.MAX_RECEIPT_BYTES`, `endpoint.MAX_REQUEST_BYTES` and
  `jws.MAX_JWS_BYTES` are gone**, and with them the `endpoint` and `jws`
  modules, which held nothing else. Nothing in the package read them: the
  module enforces the caps and answers `Reason.TOO_LARGE` (21002 at the
  endpoint). The numbers are under "Input limits" below. Go and Swift
  dropped their copies the same way.
- **Platforms follow wasmtime-py's wheels** (top of this file), where 0.7
  followed `cryptography`'s.
- **`Environment.from_receipt_type` and `Environment.from_jws_environment`
  are gone.** Read `ReceiptPayload.environment` and `JsonPayload.environment`,
  which carry the environment the module states; a JWS's also comes from a
  notification's `data.environment` and `summary.environment`. Both
  dataclasses take `environment=` (default `None`) for a payload built by
  hand.

## Upgrading from 0.6

0.7 is a breaking change: the two verifier classes are gone, policy checks
(bundle id, allowed environments) are no longer constructor arguments, and
every failure is a `VerificationResult`/`Failure` instead of a raised
`VerificationError`.

| 0.6 | 0.7 |
|---|---|
| `ReceiptVerifier(roots, bundle_id).verify(b64)` | `Verifier(Config(roots=roots)).verify_receipt(b64)`, then compare `result.payload.bundle_id` yourself |
| `JwsVerifier(roots, bundle_id, environments).verify_transaction(jws)` | `Verifier(Config(roots=roots)).verify_signed_data(jws)`, then compare `payload["bundleId"]` / `payload["environment"]` yourself |
| `apple_receipt_roots()` / `apple_jws_roots()` | `Config()` (one pinned set, for both paths) |
| raised `VerificationError` with `.reason` | `VerificationResult.failure` (`Failure.reason`, `.message`, `.cause`); nothing raises |
| `Reason.INVALID_RECEIPT_FORMAT`, `.INVALID_JWS_FORMAT` | `Reason.MALFORMED` |
| `Reason.REQUEST_TOO_LARGE` | `Reason.TOO_LARGE` |
| `Reason.INVALID_CHAIN` | `Reason.UNTRUSTED_CHAIN` |
| `endpoint.verify_receipt_result(body).to_response()` | `Verifier(...).verify_receipt_endpoint(environment, body)` (returns the JSON string directly; no `VerifyReceiptResult`, no environment re-render without re-verifying) |
| `VerifyReceiptEndpoint.MAX_REQUEST_BYTES` | `apple_purchase_receipt_verifier.endpoint.MAX_REQUEST_BYTES` (removed in 0.8; see "Input limits") |
| `ReceiptVerifier.MAX_RECEIPT_BYTES` | `apple_purchase_receipt_verifier.receipt.MAX_RECEIPT_BYTES` (removed in 0.8; see "Input limits") |
| `JwsVerifier.MAX_JWS_BYTES` | `apple_purchase_receipt_verifier.jws.MAX_JWS_BYTES` (removed in 0.8; see "Input limits") |
| transaction's `expires_date` / `.revocation_date` attributes | read the same keys straight off `json.loads(payload.json)` (there is no longer a typed JWS model, only the verified JSON text) |
| device-hash check built into `ReceiptVerifier` | `apple_purchase_receipt_verifier.receipt.device_hash(...)`, called by you (see "Device hash" above) |

## Speed

What wasmtime-py 49.0.0 measured on the release module (2026-09-29, one thread,
Linux x86_64, CPython 3.11, on a shared 4-CPU runner that was busy the whole
time, so read them as upper bounds; `docs/evidence/2026-09-29-python-g1.md`
holds the sources): 2.2 to 3.0 ms of CPU for a genuine sandbox receipt with two
purchases, 18 ms for one with 187, and 8 ms for a StoreKit 2 JWS, after the
module is compiled (at most about 450 receipts per second per thread), a new
`Verifier` about 3 ms once it is, and the start-up figures at the top of this
file. Peak memory is 150 MB after a compile and 54 MB after a cache hit, and
does not grow over 300 calls. The core does the same work for a
hostile input as for an ordinary one of its size, and its bounds are its own
(see "Input limits"), so a large or malformed input costs no more than a large
valid one.

`uv run --locked python bench/bench.py` times the cross-port operations on the
two genuine sandbox receipts on your machine, and with `--worst-case` every
case of `fixtures/cases.json` that carries a time budget (it needs the release
module, whose answers the cases pin). `../BENCHMARKS.md` compares all the ports.

## Debugging a receipt by hand

See the [project README](../README.md#debugging-a-receipt-by-hand) for the
`openssl` commands that open a receipt or a JWS payload without verifying
it (useful when a verification fails and you want to see what arrived).

## Input limits

Base64 decoding and JSON parsing both allocate a multiple of their input
before any signature is checked, so the input is measured first. The byte
limits are Apple's, fixed in the module for every package of this
library, not `Config` options. The package exports none of them: the
module enforces each one, and its `TOO_LARGE` answer says an input
exceeded one. They are the core's bounds, listed in
[docs/rust-core/SURFACE.md](../docs/rust-core/SURFACE.md) §5.

- **Receipt** (3 MiB, 3,145,728 bytes): the base64 text given to
  `verify_receipt`, in UTF-8 bytes, before decoding. A larger receipt is
  `Reason.TOO_LARGE`.
- **Endpoint request body** (3 MiB, 3,145,728 bytes): the body given to
  `verify_receipt_endpoint`, before it is parsed. A larger body is
  `Reason.TOO_LARGE` (status 21002).
- **JWS** (256 KiB, 262,144 bytes): the compact JWS text given to
  `verify_signed_data`, before it is split into segments. A larger JWS is
  `Reason.TOO_LARGE`.
- **JSON nesting**: no bound of its own. The module skips a value nobody
  reads in the request body, the JWS header or the JWS payload without
  building it, so only the size caps bound it
  (docs/rust-core/DECISIONS.md R40).
- **ASN.1 nesting depth 32**: checked before any certificate is decoded.
  Deeper input is `Reason.MALFORMED` in the CMS envelope and
  `Reason.UNREADABLE_PAYLOAD` in the signed receipt content.

`fixtures/cases.json` holds every port to these same numbers, from both
sides of each boundary.

The package copies at most as many bytes of any input into the module as the module's `init` answer states (`max_input_bytes`, one over the cap: 3,145,729 today; the package keeps no copy of the number), so the module itself answers `TOO_LARGE` and a huge input costs no memory.

## Why offline

Signature verification cannot fail because a vendor endpoint is down, so a
purchase can be honoured immediately and reconciled against the App Store
Server API afterwards. Refunds and revocations still need that reconciliation
pass — a signature proves what Apple signed, not what happened since.

This package holds no verification code. It runs the project's Rust core,
compiled once to WebAssembly, as the other Wasm-hosted packages do; the shared
fixture suite `fixtures/cases.json`, including Apple's own official test
fixtures, is the contract every package meets, and `tests/test_conformance.py`
runs all of it. See the [project README](../README.md) for the full picture and
[COMPARISON.md](../COMPARISON.md) for how it differs from Apple's official
libraries.

## Licence

MIT — see [LICENSE](../LICENSE).
