# ApplePurchaseReceiptVerifier (.NET)

Verify Apple in-app purchases locally, with no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS payloads and legacy PKCS#7 app receipts against pinned Apple root
certificates.

```
dotnet add package ApplePurchaseReceiptVerifier
```

```csharp
using ApplePurchaseReceiptVerifier;

// Build once, share everywhere: the module is compiled and the roots are
// parsed once, not per call (about a second, the first time in a process).
// Thread-safe, immutable and never disposed: it copies the certificates you
// hand it, so you may dispose your own X509Certificate2 instances right
// after constructing the Config.
IVerifier verifier = Verifier.Create(new Config());

// A legacy app receipt, as the base64 string the app sends.
VerificationResult<ReceiptPayload> receiptResult = verifier.VerifyReceipt(receiptBase64);
if (receiptResult.Verified)
{
    Console.WriteLine($"{receiptResult.Payload.ReceiptType} {receiptResult.Payload.InApp.Count}");
}

// Any Apple-signed JWS: a transaction, renewal info, an app transaction or
// a notification. The payload comes back as the JSON text Apple signed.
VerificationResult<JsonPayload> jwsResult = verifier.VerifySignedData(jws);
if (jwsResult.Verified)
{
    Console.WriteLine(jwsResult.Payload.Json);
}
```

Targets `netstandard2.0` and `net8.0`. The netstandard2.0 asset reaches .NET
Framework 4.6.2+, Mono 6.x and every .NET Core / .NET 5–10 runtime from one
binary; the net8.0 asset is trim- and AOT-annotated. No method throws for
input the caller does not control: every verify call returns a
`VerificationResult<T>`, never a thrown exception, for anything short of an
`OutOfMemoryException`.

Everything that verifies runs inside one WebAssembly module, `aprv.wasm`,
embedded in the assembly and run by [Wasmtime](https://github.com/bytecodealliance/wasmtime-dotnet)
(the `Wasmtime` NuGet package; on netstandard2.0 the package also takes
`System.Text.Json`, see [How it runs](#how-it-runs)). This library
parses no receipt, checks no signature and decides no trust: it moves bytes
in, reads a JSON answer back, and maps it to the types below. Read
[How it runs](#how-it-runs) before deploying it on Alpine or in a
memory-limited container.

The library answers one question: did Apple sign this? It checks the chain
to a pinned root, Apple's marker OIDs and the signature, and hands back
everything the payload says. Whether the payload is for your app, your
environment, your user and still current is your decision, made on the
fields it returns ([What to check after verification](#what-to-check-after-verification)).

## What it will never do

These are the properties the library exists to hold.

- **It never reads the operating system's trust store.** `X509Chain` is
  never constructed anywhere in this library, and a `BannedApiAnalyzers`
  rule makes writing one a compile error. Its defaults are the operating
  system's trust store plus online revocation and AIA fetching — and on a
  developer's macOS or Windows machine, where the Apple roots are already
  in the OS store, forgetting the pin fails *permissively*. Anchors come
  from `new Config(roots: ...)`, or from `new Config()`, whose roots are
  Apple's three published roots pinned inside the module,
  so they work unchanged in a container with no filesystem access.
- **It never touches the network.** No OCSP, no CRL, no AIA fetch, no root
  download. Revocation checking is disabled by design; an integrator who
  needs it must layer it on top.
- **It never uses a key no pinned root vouched for.** The chain is built
  top-down, from the pinned roots, so a certificate carrying an attacker's
  key (their choice of size and curve) is never used to check anything
  ([Stranger certificates](#stranger-certificates)).
- **It never returns anything partial.** A failed result carries a
  `Failure` and a `null` `Payload`; a verified one carries a `Payload` that
  passed every check, and a `null` `Failure`. `Verified` is annotated
  `[MemberNotNullWhen]`, so `if (result.Verified)` gives the compiler a
  non-null `result.Payload`.
- **It never logs, meters or calls back into your code** except for the
  clock you give it. `VerificationReason` is the whole observability
  surface, and `Failure.Message` never quotes the input.

## The API

### `Config`: the roots and the clock

```csharp
Config defaults = new Config(); // the module's Apple roots, the system clock

Config pinned = new Config(
    roots: new[] { rootCertificate },          // replaces the defaults
    clock: () => 1_735_689_600_000L);          // epoch milliseconds; replaces DateTimeOffset.UtcNow
```

The constructor is the one way to build a `Config`. Both arguments are
optional, and `null` for either means its default. `roots` takes any
`IEnumerable<X509Certificate2>`; its DER is copied when the `Config` is
constructed.

`Roots` is either your own list of trust anchors or, by default, nothing:
the three Apple roots are pinned inside the module, and `Config` lists none
of them (`new Config().Roots` is empty), and the package ships no copy.
To trust Apple's roots and one of your own, pass all four, loading Apple's
three from its PKI page or the repository's `certs/`. An empty `Roots` set that you pass in is an
`ArgumentException` from the constructor, never a verdict: a verifier with no
roots would reject everything, and nobody would notice until production.
`Verifier.Create` throws `ArgumentException` for a root the module cannot
read, and `InvalidOperationException` when the embedded module is not the
one this library was built for; check for both at startup.

The clock is read once per call, before the input is looked at, and the
value goes to the module. A clock that throws, or answers a negative time,
is an `InternalError` with the exception as its cause.

### `Verifier.Create`: three methods

| Method | Input | Result |
|---|---|---|
| `VerifyReceipt(string base64)` | the base64 receipt an app sends | `VerificationResult<ReceiptPayload>` |
| `VerifySignedData(string jws)` | any Apple-signed compact JWS | `VerificationResult<JsonPayload>`: `{ Json }`, the signed JSON text |
| `VerifyReceiptEndpoint(AppleEnvironment environment, string requestJson)` | a `verifyReceipt` request body | Apple's response body, as a JSON string, always |

`VerificationResult<T>` carries exactly one of `Payload` and `Failure` — check
`result.Verified` before touching either. The endpoint never fails to
answer: the Apple status code is a field of the body, for every input.

### `ReceiptPayload`

Every field is `null` when the attribute is absent or does not decode, so a
caller can build one by hand with the public constructor for its own tests.
Dates are epoch milliseconds (`*Ms`, `long?`); 64-bit ids (`AppItemId`,
`DownloadId`, `VersionExternalIdentifier`, an in-app purchase's
`WebOrderLineItemId`) stay `long?` on this payload but render as decimal
**strings** in `ToJson()`, the same JSON value every port writes.

```csharp
payload.ReceiptType;               // "Production", "ProductionSandbox", ...
payload.BundleId;                  // decoded attribute 2
payload.BundleIdBytes;             // its raw octets: the device-hash input
payload.ReceiptCreationDateMs;
payload.InApp[0].ProductId;
payload.InApp[0].ExpiresDateMs;
payload.UnknownAttributes;         // IReadOnlyDictionary<int, IReadOnlyList<byte[]>> in receipt order
payload.ToJson();                  // JSON with the same value in every port
```

Decoding follows the rules every port shares: the first occurrence of an
attribute wins; every attribute that does not end up in a typed field (a
later copy, or a value that does not decode, whose field is then `null`) is
kept raw in `UnknownAttributes`, the in-app ones in that purchase's own; an
empty date string means "not set" and is not kept raw. `ToJson()` writes
JSON whose parsed value is the same in every port; the bytes may differ.

### `Failure` and `VerificationReason`

`Failure` is `{ Reason, Message, Cause }`. `Reason` and `Message` are the
module's verdict. `Cause` is non-null only for an `InternalError` this
library raised itself: the module trapped, its answer could not be read, or
the clock failed. A verdict of the module, `InternalError` included, has no
cause. Switch on `Failure.Reason`; never parse `Failure.Message`.
`VerificationReasonCodes.ToCode` gives the SCREAMING_SNAKE token every port
reports (e.g. `"UNTRUSTED_CHAIN"`) for logging or telemetry.

To stand in for `IVerifier` in your own tests, build results by hand:
`VerificationResult<ReceiptPayload>.Of(payload)`,
`VerificationResult<ReceiptPayload>.Failed(new Failure(reason, message, cause))`.

| `VerificationReason` | Raised when | Endpoint status |
|---|---|---|
| `Malformed` | the base64, ASN.1, CMS or JWS structure is broken, or a structural bound is exceeded | 21002 |
| `TooLarge` | the input is over its size cap and was not decoded | 21002 |
| `InvalidSignature` | the signature did not verify | 21003 |
| `UntrustedChain` | the chain does not reach a pinned root | 21003 |
| `InvalidCertificate` | a certificate does not decode, or is outside its validity window at the chain instant | 21003 |
| `InvalidCertificatePurpose` | a certificate lacks Apple's marker OID for its place | 21003 |
| `UnreadablePayload` | the chain and signature passed, but the signed content does not parse | 21009 |
| `InternalError` | the module failed or trapped, its answer could not be read, or the configured clock threw; no input makes a correct library answer it | 21009 |

`UnreadablePayload` and `InternalError` are not the client's fault: alert,
log the failure, and reconcile the purchase through the App Store Server API
rather than deny the user.

## What to check after verification

The library proves Apple signed the payload. Before granting anything, check
what it says:

```csharp
VerificationResult<ReceiptPayload> result = verifier.VerifyReceipt(receiptBase64);
if (!result.Verified)
{
    return Denied(result.Failure.Reason);
}
if (result.Payload.BundleId != "com.example.app")
{
    return Denied("other app");
}
```

For a JWS, deserialize `result.Payload.Json` into a struct your own code
declares — this library ships no typed claim models, since .NET (like Go,
Rust, Ruby and PHP among the other ports) has no
[`app-store-server-library`](https://github.com/apple/app-store-server-library-dotnet)
of its own to lean on here; if you already depend on one, that package's
types are exactly what to deserialize into. Read `bundleId`, `environment`,
`appAppleId` for a Production `AppTransaction`, `revocationDate`,
`expiresDate`, and `signedDate` for freshness. No payload is rejected for
its age, as in Apple's own libraries: the right limit depends on the
endpoint (Apple retries a server notification for days), so apply one
yourself:

```csharp
long signedDate = /* from the deserialized JSON */;
bool tooOld = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - signedDate > 5 * 60 * 1000;
```

**The device hash** is yours too, when you have the device's identifier —
the raw bytes of `identifierForVendor` on iOS, iPadOS, tvOS and watchOS
(including an iOS app running on an Apple silicon Mac), or the primary
network interface's MAC address from `copy_mac_address` on macOS and Mac
Catalyst:

```csharp
using System.Security.Cryptography;

byte[] expected;
using (SHA1 sha1 = SHA1.Create())
{
    sha1.TransformBlock(deviceIdBytes, 0, deviceIdBytes.Length, null, 0);
    sha1.TransformBlock(payload.OpaqueValue!, 0, payload.OpaqueValue!.Length, null, 0);
    sha1.TransformFinalBlock(payload.BundleIdBytes!, 0, payload.BundleIdBytes!.Length);
    expected = sha1.Hash!;
}
bool matches = CryptographicOperations.FixedTimeEquals(expected, payload.Sha1Hash);
```

**Deduplicate on transaction ids, never on the receipt or JWS bytes.** A
legacy receipt is BER, and one correctly signed receipt can be re-chunked
into different byte strings that carry the same signed content.

### App Store Server Notifications V2

A notification nests more JWS inside its own payload. Apple POSTs
`{"signedPayload": "<JWS>"}`; verify that, then verify whichever of
`data.signedTransactionInfo` and `data.signedRenewalInfo` the notification
payload carries — a `TEST` notification carries neither:

```csharp
VerificationResult<JsonPayload> outer = verifier.VerifySignedData(signedPayload);
if (!outer.Verified) return Denied(outer.Failure!.Reason);

using JsonDocument notification = JsonDocument.Parse(outer.Payload!.Json);
JsonElement data = notification.RootElement.TryGetProperty("data", out JsonElement d) ? d : default;

if (data.ValueKind == JsonValueKind.Object && data.TryGetProperty("signedTransactionInfo", out JsonElement txJws))
{
    VerificationResult<JsonPayload> transaction = verifier.VerifySignedData(txJws.GetString()!);
    if (!transaction.Verified) return Denied(transaction.Failure!.Reason);
    // ... read the transaction's own claims from transaction.Payload.Json
}

if (data.ValueKind == JsonValueKind.Object && data.TryGetProperty("signedRenewalInfo", out JsonElement renewalJws))
{
    VerificationResult<JsonPayload> renewal = verifier.VerifySignedData(renewalJws.GetString()!);
    if (!renewal.Verified) return Denied(renewal.Failure!.Reason);
}
```

## What the checks are, and in what order

The module makes these checks. The order is observable and is part of the
contract every port shares (`docs/design/0.7-api.md`): an input that fails
an early check reports that check's reason, not a later one.

**JWS.** Size cap → three segments, each strict base64url → header JSON
(strict UTF-8, no byte order mark, nothing but whitespace after the object),
`alg` ES256 and exactly three `x5c` entries → the certificates decode and
are structurally sound (X.509 version 1–3, no duplicate extension, no
undecodable extension) → the chain at `signedDate` (or the clock), the
intermediate checked against the pinned roots **before** the leaf is
checked against the intermediate → **leaf marker OID**
`1.2.840.113635.100.6.11.1` → **intermediate marker OID**
`1.2.840.113635.100.6.2.1` → ES256 signature. A chain that does not reach a pinned root is
`UntrustedChain` whatever markers it carries; validity is part of the chain
check, so an expired chain that lacks a marker, or has a broken signature,
is `InvalidCertificate` (owner decision, 2026-09-27).

**Receipt.** Size cap → strict base64 → CMS parse, including the syntax of
every `SignerInfo`'s signed attributes, whatever its position → at most four
`SignerInfo`s and ten embedded certificates → the creation date alone
(nothing else in the payload is read yet) → for each `SignerInfo`, in bag
order: the signer's certificate looked up among the embedded certificates by
issuer and serial number → structurally sound → the chain, top-down from the
pinned roots, at the creation date or the clock → **signer marker OID** →
**WWDR marker OID on the intermediate** → the CMS signature. One `SignerInfo` passing is enough; when none
does, the first one's failure is the verdict. Then the full payload parse,
where any failure is `UnreadablePayload`.

The receipt signer may use any algorithm the module implements: RSA
PKCS#1 v1.5, RSA-PSS or ECDSA over the hashes it supports. A signer that
chains to a pinned root and carries Apple's marker is trusted whatever it
signs with, so a change on Apple's side does not reject genuine receipts.
The same goes for certificate signatures in the chain: no fixed allowlist
(owner decision, 2026-09-27). A `signatureAlgorithm` that names a
hash (`sha256WithRSAEncryption`, `ecdsa-with-SHA384`, the RSA-PSS
parameters) must name the `SignerInfo`'s `digestAlgorithm`, or the signature
is `InvalidSignature`; `rsaEncryption` and `id-ecPublicKey` name none and
take the digest.

The three roots are pinned inside the module, and the repository's `certs/`
holds the canonical copy; the assembly's SHA-256 check of its embedded
module is described under [How it runs](#how-it-runs).

`x5c[2]` is never compared to an anchor and never trusted, and neither is a
receipt's embedded copy of its root: the chain terminates at an anchor the
caller pinned. Trust anchors are trusted by fiat, so **an anchor's own
expiry is not checked**, which is what lets a receipt signed years ago
under a since-expired chain verify at its own creation date.

A certificate on the path (not the anchor) that marks critical an extension
a PKIX validator does not process makes the path `UntrustedChain`, as it
does for a PKIX validator. Processed are keyUsage, basicConstraints,
certificatePolicies, policyMappings, policyConstraints, inhibitAnyPolicy,
nameConstraints, subjectAltName, issuingDistributionPoint and
deltaCRLIndicator, and on the leaf also cRLDistributionPoints and
extKeyUsage. In signed attributes, `contentType` or `messageDigest` twice,
or a `contentType` that differs from the `eContentType`, is
`InvalidSignature`.

An embedded certificate that does not decode is fatal, and the reason
depends on which one it is: the **signer** is `InvalidCertificate`, any
other entry `Malformed`, because the certificate bag is unsigned. An issuer
whose `keyUsage` extension is present but does not permit `keyCertSign`
cannot issue anything, and one whose `keyUsage` is present but does not
decode fails closed the same way; an issuer with no `keyUsage` extension at
all is permitted, as PKIX allows.

### Stranger certificates

A receipt's certificate bag is not signed, so anyone can add to it. A
certificate there that no pinned root vouches for, directly or through a
certificate it vouched for, is ignored: it never reaches the path builder
and its key is never used, so a genuine receipt padded with such
certificates still verifies. The walk starts at the roots, so the cost of a
stranger is a name comparison, however large or broken its key. The shared
denial-of-service cases pin this with a `maxMillis` time budget.

## Input limits

Base64 decoding, ASN.1 parsing and JSON parsing all allocate in proportion
to their input, and all of them run before any signature is checked. So
each input is measured first. The caps are fixed constants, the same in
every port of this library. They are not options.

The receipt and request caps are Apple's own limit. Measured on 2026-09-23
against both of Apple's verifyReceipt endpoints (production and sandbox), a
request body of 3,145,728 bytes is answered normally and one of 3,145,729
bytes gets HTTP 413. Apple counts UTF-8 bytes, not characters.
`fixtures/cases.json` holds every port to these numbers from both
sides.

- **the endpoint request body and the receipt base64 string**: 3,145,728
  UTF-8 bytes. Over it is `TooLarge`, 21002 at the endpoint (Apple answers
  HTTP 413 there — check the body's length before the call to do the
  same).
- **the compact JWS**: 262,144 UTF-8 bytes, `TooLarge`.
- **ASN.1 nesting depth 32.** A deeper CMS envelope is `Malformed`; deeper
  signed receipt content is judged after the signature: `UnreadablePayload`
  if it verifies, `InvalidSignature` if not. JSON has no nesting bound of
  its own: the module skips a value nobody reads without building it, so
  only the size caps bound a request body or a JWS
  (docs/rust-core/DECISIONS.md R40).

`receipt-data` is decoded exactly as Apple's `verifyReceipt` accepts it:
standard base64 with canonical `=` padding and nothing else — whitespace,
base64url and omitted or extra padding are all refused, as at Apple. `x5c`
entries are standard base64, JWS segments unpadded canonical base64url, so
one signed payload has one accepted spelling.

## Speed and start-up

Measured on 2026-09-29 through the host layer (`dotnet/tools/CorpusRun`),
.NET 10.0.12, Wasmtime 48.0.2, Linux x86-64 in a 4-vCPU guest shared with
five other builds (load average 8 to 18 during the runs), so treat the
numbers as an order of magnitude. The module was the release build.

- **Compile at start:** the first `Verifier.Create` in a process compiles
  the module with Cranelift: 0.9 to 1 s on an idle 4-CPU machine in the
  earlier evidence, 7.7 to 12.3 s on the loaded one here. It happens once
  per process, not per verifier.
- **Instances:** the first instance and its `init` took 56 to 81 ms here;
  later instances 4 to 7 ms at the median (`init` reads the three built-in
  roots).
- **Throughput:** one genuine G5 receipt per call through the host layer took
  215 to 379 per second on one thread and 237 to 510 per second on four
  threads with one instance each; a JWS 55 to 95 and 64 to 92. The earlier
  evidence, on an idle machine, measured 763 and 2,475 receipts per second
  and 227 and 669 JWSs, so the gap is mostly the other builds' load.
  Details are in `docs/evidence/2026-09-29-dotnet-host.md`.

Run `dotnet run -c Release --project dotnet/bench` for the genuine receipts
and `-- --worst-case` for the hostile cases on your own hardware.

## How it runs

- **One module, one hash.** `aprv.wasm` is embedded in both target
  frameworks. Its SHA-256 is checked against the hash embedded beside it the
  first time a verifier is created, and a mismatch is an
  `InvalidOperationException`. The module imports exactly one function,
  `random-get`, answered from `RandomNumberGenerator`; anything else it asks
  for is refused.
- **Input cap.** At most 3,145,729 bytes of an input (one over the largest cap) are copied into the module's memory; the core decides every cap on the length, so a longer input gets the `TooLarge` answer (21002 at the endpoint) it would get whole.
- **Instances.** One compiled module per process. Each `IVerifier` owns a
  small pool of instances, each in a `Store` of its own limited to one
  instance and 256 MiB of linear memory. A call takes an idle instance or a
  new one, uses it alone, and hands it back; an instance that trapped, that
  answered something unreadable, or that grew past 64 MiB is thrown away
  and the next call takes another. Nothing needs closing.
- **Address space, not memory.** Wasmtime reserves about 4 GiB of *virtual*
  address space for each instance's linear memory, so 32 live instances show
  about 188 GB of virtual size and about 32 MiB more resident memory than none
  (measured on Linux x86-64; `CorpusRun memory 32`). An instance holds about
  1.9 MiB of linear memory after `init`. Nothing is committed beyond that,
  so container memory limits are unaffected, but an environment that caps
  virtual size (`ulimit -v`, strict overcommit) has to allow for it. The pool
  keeps at most as many idle instances as there are CPUs, and never fewer
  than two.
- **Native library.** Wasmtime brings a native library per platform:
  `linux-x64` (glibc 2.28), `linux-arm64` (glibc 2.18), `osx-x64`,
  `osx-arm64`, `win-x64`, `win-arm64`. The package has no 32-bit or musl
  build.
- **Alpine and other musl distributions** fall back to the glibc library,
  which is expected to fail to load without a glibc compatibility layer
  (`gcompat`). This has not been run here. Alpine users take `aprv-server`,
  the same module in a static binary that ships for musl, and call it over
  HTTP.
- **Windows and CET.** An application built with the .NET 9 or later SDK has
  the hardware shadow stack (CET) flag in its apphost. Under it Wasmtime's
  recovery from a guest trap ends the process (exit code -1073740791,
  `0xC0000409`) instead of surfacing the trap, so the wrapper cannot turn it
  into `INTERNAL_ERROR`. This library's own Windows CI showed it (net8.0
  apphosts do not), and it is reported upstream
  (bytecodealliance/wasmtime-dotnet#374). A trap is a defect in the module or a
  misused ABI and none of the shared corpora causes one; an application that
  wants the wrapper to survive one sets `<CETCompat>false</CETCompat>`. Not
  run here: there is no Windows machine.
- **Dependencies.** `Wasmtime` on both assets. The module's answers are
  read, and `ReceiptPayload.ToJson` written, with `System.Text.Json`
  (`JsonDocument` and `Utf8JsonWriter`, no reflection serializer): in the
  box on net8.0, a package on netstandard2.0. That package (10.0.12) brings
  `Microsoft.Bcl.AsyncInterfaces`, `System.IO.Pipelines` and
  `System.Text.Encodings.Web` (10.0.12) and
  `System.Threading.Tasks.Extensions` (4.6.3), and raises `System.Buffers`
  to 4.6.1, `System.Memory` to 4.6.3, `System.Numerics.Vectors` to 4.6.1
  and `System.Runtime.CompilerServices.Unsafe` to 6.1.2. A Unity or .NET
  Framework project that already ships `System.Memory`,
  `System.Runtime.CompilerServices.Unsafe` or any other of these through
  other packages can get duplicate-assembly errors or binding-redirect
  conflicts. On .NET Framework, binding redirects to the higher version fix
  it (SDK-style projects generate them); in Unity, keep one copy of each
  assembly, the higher version.
- **.NET Framework, Mono and Unity.** The netstandard2.0 asset compiles and
  is exercised on modern .NET; whether .NET Framework or Mono find the native
  library under `runtimes/` depends on the consuming project, and was not run.
  Unity's IL2CPP has not been tried.
- **No operating-system crypto.** Verification uses the crypto compiled into
  the module, not the system's OpenSSL, CNG or Security framework, so the
  platform crypto policies of 0.7 (for example RHEL 9's refusal of SHA-1
  signatures) no longer apply.

## The endpoint

```csharp
string body = verifier.VerifyReceiptEndpoint(AppleEnvironment.Production, rawRequestBody);
```

`rawRequestBody` must be the request's raw JSON text. A framework whose
model binder defaults to `application/x-www-form-urlencoded` (or that only
populates a parsed body after reading it that way) will hand this method a
stringified form object, not the JSON Apple's client actually sent, and
`receipt-data` will read as missing. Read the body as `application/json`
before calling this method — `await new StreamReader(Request.Body).ReadToEndAsync()`
in ASP.NET Core, not a model-bound form object — or parse it yourself and
re-stringify it.

| Status | Meaning |
|---|---|
| `0` | verified, and the receipt matches the requested environment |
| `21002` | `receipt-data` is missing, malformed, or over the size cap |
| `21003` | the receipt did not authenticate |
| `21007` | a Sandbox receipt was sent to `AppleEnvironment.Production` |
| `21008` | a Production receipt was sent to `AppleEnvironment.Sandbox` |
| `21009` | not the client's fault: alert and reconcile, do not deny |

`AppleStatus` holds these (and the codes Apple's own servers can return,
which this local stand-in never produces) as named `int` constants. Local
21007 / 21008 routing fails closed: only receipt types `Production` and
`ProductionVPP` count as production (`AppleEnvironments.FromReceiptType`).
Like Apple's endpoint, this does **not** check the bundle id: compare
`receipt.bundle_id` in the response before granting anything. `password`
and `exclude-old-transactions` are accepted for wire compatibility and
never read. Fields that exist only in Apple's server-side database
(`latest_receipt_info`, `pending_renewal_info`, `latest_receipt`) are never
produced. 64-bit ids (`adam_id`/`app_item_id`/`download_id`/
`version_external_identifier`) are written as raw JSON numbers, exactly as
Apple's own endpoint does, even though `ReceiptPayload.ToJson()` renders
them as decimal strings; `*_ms` date fields are JSON strings. A field the
receipt does not carry is left out of the response entirely, never sent as
JSON `null`. See
[COMPARISON.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/COMPARISON.md)
for the field-by-field fidelity account.

`*_pst` fields are rendered in `America/Los_Angeles`. Before 1883-11-18
the offset is tzdb's local mean time, -07:52:58, fixed in code on every
platform. From that date on the system time zone data answers. Linux and
macOS read tzdb. Windows uses its own zone data, whose rules before 1987
can differ from tzdb's, so a `_pst` value from 1883 to 1986 can differ
there. Genuine receipts carry no dates that old, so only hand-made input
reaches this.

## Why offline

Signature verification cannot fail because a vendor endpoint is down, so a
purchase can be honoured immediately and reconciled against the App Store
Server API afterwards. Refunds and revocations still need that
reconciliation pass — a signature proves what Apple signed, not what
happened since.

This is one of nine implementations (Java, Node, Python, Swift, Go, Ruby,
Rust, PHP, .NET) that share a single fixture suite, including Apple's own
official test fixtures, and are required to agree on every verdict and
every decoded value. See the
[project README](https://github.com/emindeniz99/apple-purchase-receipt-verifier#readme)
for the full picture and
[COMPARISON.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/COMPARISON.md)
for how it differs from Apple's official libraries.

## Upgrading from 0.7

The API is unchanged but for `AppleRootCertificates`, which is gone, and
`Config`, which is now built with its constructor alone; what runs under
it is not.

| 0.7 | 0.8 |
|---|---|
| verification in C#, on `System.Security.Cryptography.Pkcs` and `System.Formats.Asn1` | verification in `aprv.wasm`, hosted by the `Wasmtime` package; those two packages are no longer dependencies, and the netstandard2.0 asset takes `System.Text.Json` (see [How it runs](#how-it-runs)) |
| `Config.Defaults()` | `new Config()` |
| `Config.CreateBuilder().Roots(roots).Clock(clock).Build()` | `new Config(roots: roots, clock: clock)`, passing only what differs from the defaults; `Config.Builder` is gone |
| `Config.Defaults().Roots` lists Apple's three roots | it is empty: the roots are pinned inside the module. To trust Apple's roots and your own, pass all four |
| `AppleRootCertificates.Bundled()` returns Apple's three roots | removed: the package ships no copy of them. Load them from Apple's PKI page or the repository's `certs/` |
| `Config.Defaults()` throws if the bundled roots do not load | it cannot fail; `Verifier.Create` throws `ArgumentException` for a root the module refuses and `InvalidOperationException` for a module of another ABI version |
| `ReceiptPayload.ToJson()` escapes only the quotation mark, the reverse solidus and the controls, in lower-case hex | it escapes the way `System.Text.Json`'s `UnsafeRelaxedJsonEscaping` does: upper-case hex, and `\u` escapes for U+007F to U+009F, U+2028, U+2029, private-use, noncharacter and unassigned code points, U+FEFF and every character outside the BMP (as a surrogate pair). The text can differ from 0.7's in escaping only; the JSON value is the same, except that a lone surrogate in a payload you build yourself is written as `\uFFFD` (the module's strings never hold one) |
| `Failure.Cause` set for `UnreadablePayload` and `InternalError` | set only for an `InternalError` raised by this library (a trap, an unreadable answer, the clock) |
| `Verifier.Create` takes microseconds | the first one in a process compiles the module, about a second on an idle machine and several under load |
| any platform .NET runs on | the platforms Wasmtime ships a native library for; no Alpine, no 32-bit |
| SHA-224 receipts could not be verified | the module decides which algorithms verify |

## Upgrading from 0.6

0.7 replaces the three constructed verifiers with one `IVerifier` built
from a `Config`, and takes no policy: no bundle id, no accepted
environments, no app Apple id, no device id. Methods return a
`VerificationResult<T>` instead of throwing, and no longer accept raw DER
— only the base64 string an app actually sends.

| 0.6 | 0.7 |
|---|---|
| `new ReceiptVerifier(roots, bundleId).Verify(base64 \| der)` | `Verifier.Create(Config.CreateBuilder().Roots(roots).Build()).VerifyReceipt(base64)`, then compare `payload.BundleId` |
| `ReceiptVerifier.VerifyReceiptCore(der, roots)` | base64-encode, then `VerifyReceipt` |
| `Verify(base64, deviceGuid)` (device-hash checking on the verifier) | compute the hash yourself from `OpaqueValue` and `BundleIdBytes` (above) |
| `new JwsVerifier(roots, bundleId, acceptedEnvironments).VerifyTransaction/VerifyAppTransaction/VerifyRaw(jws)` | `verifier.VerifySignedData(jws)`, then deserialize `payload.Json` yourself |
| `new VerifyReceiptEndpoint(roots, environment).VerifyReceiptJson(body)` | `verifier.VerifyReceiptEndpoint(environment, body)` |
| `AppleRootCertificates.JwsRoots()`, `AppleRootCertificates.ReceiptRoots()` | `Config.Defaults()` (one set, shared by every method) |
| a `DateTimeOffset` argument for `request_date` | `Config.CreateBuilder().Clock(() => epochMs)` |
| `VerificationException` (thrown) | `result.Failure` (`{ Reason, Message, Cause }`, never thrown for input) |
| `AppReceipt` (`DateTimeOffset` fields) | `ReceiptPayload` (`*Ms` epoch milliseconds) |

| 0.6 `VerificationReason` | 0.7 `VerificationReason` |
|---|---|
| `InvalidJwsFormat`, `InvalidReceiptFormat`, `MalformedRequest` | `Malformed` |
| `RequestTooLarge` | `TooLarge` |
| `InvalidChain` | `UntrustedChain`, or `InvalidCertificate` for a certificate outside its validity window |
| `InternalError` for signed content that does not parse | `UnreadablePayload` |
| `WrongBundleId`, `WrongEnvironment`, `WrongAppAppleId`, `DeviceHashMismatch` | gone: the caller's own checks |

## Testing

`aprv.wasm` is not committed: copy the module to `dotnet/src/ApplePurchaseReceiptVerifier/wasm/aprv.wasm` (listed in `.gitignore`; its SHA-256 is in `aprv.wasm.sha256` beside it), or set `APRV_WASM` to its path; a missing file stops the build with a message.

```bash
dotnet test dotnet/tests/ApplePurchaseReceiptVerifier.Tests           # the whole suite
dotnet test dotnet/tests/ApplePurchaseReceiptVerifier.Tests.Floor     # the netstandard2.0 asset, loaded into net8.0/9.0/10.0
```

`Conformance070.cs` runs every case in `fixtures/cases.json`, the
normative cross-language vector file every port of this library answers,
as one named test per case, and fails unless every case in the file ran.
The adapter carries no case-specific knowledge: it builds a `Config` from
the case, dispatches on the operation and evaluates the expected JSON
Pointers on the result. A case with a `maxMillis` budget is timed after a
warm-up call. The `decodeBase64` cases run through the module, which is the
only decoder there is, and are judged on which side of the rule each text
lands, since a host cannot read the decoded bytes.

The other tests are about the wrapper, not the module:

- `AbiTests` calls the canonical ABI by hand over the real module: `init`
  and its misuse, the environment values that trap, a `random-get` answering
  the wrong length, isolation between instances, and memory that stays the
  same size over 2,000 calls.
- `FacadeTests` runs the six outcomes against a hand-assembled module
  (`StubModule`) that speaks the same ABI: a verdict, a trap, an unreadable
  answer, a return pointer outside the memory, a module of another version
  or with another import, and the post-return that must happen once per call.
- `ModuleAnswersTests`, `ClockTests`, `RootsTests`, `CultureTests` and
  `PlatformTests` cover reading the wire, the clock read, the roots that
  reach `init`, culture independence and four threads on one verifier.
- `Tests.Floor` loads the library as its netstandard2.0 asset and runs a
  slice of the same fixtures, read through the endpoint's status.

`dotnet/tools/CorpusRun` runs the shared corpora (1,179 rows and 5,000
mutants) through the host layer and prints rows for
`docs/evidence/2026-09-29-canonical-abi-final/py/classify.py`.

This environment is Linux-only: the Windows and macOS legs of the test
matrix were not exercised here and need CI or a local run on those
platforms to confirm.

## Changelog

One version across every language —
[CHANGELOG.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/CHANGELOG.md)
/ [releases](https://github.com/emindeniz99/apple-purchase-receipt-verifier/releases).

## License

MIT.
