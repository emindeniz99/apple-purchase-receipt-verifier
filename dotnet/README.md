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

// Build once, share everywhere: the roots are parsed once, not per call.
// Thread-safe, immutable, and — unlike the 0.6 verifiers — implements no
// IDisposable: it copies the certificates you hand it, so you may dispose
// your own X509Certificate2 instances right after Build().
IVerifier verifier = Verifier.Create(Config.Defaults());

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

Dependencies: `System.Security.Cryptography.Pkcs` and `System.Formats.Asn1`,
both first-party. There is no JSON dependency — the package carries its own
bounded reader, because `System.Text.Json` is a NuGet package below net8.0
and an assembly compiled against a newer one than the host ships will not
load.

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
  from `Config.CreateBuilder().Roots(...)`, or from `Config.Defaults()`,
  which holds Apple's three published roots compiled in as source
  constants, so they work unchanged in a container with no filesystem
  access.
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
Config defaults = Config.Defaults(); // Apple's three roots, the system clock

Config pinned = Config.CreateBuilder()
    .Roots(new[] { rootCertificate })          // replaces the defaults
    .Clock(() => 1_735_689_600_000L)           // epoch milliseconds; replaces DateTimeOffset.UtcNow
    .Build();
```

An empty `Roots` set is an `ArgumentException` from `Build()`, never a
verdict: a verifier with no roots would reject everything, and nobody would
notice until production. `Config.Defaults()` throws
`InvalidOperationException` if the bundled roots are missing or unreadable —
check for that at startup, since a call made with a config it fails to
produce would never exist.

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
**strings** in `ToJson()`, matching the canonical form every port shares.

```csharp
payload.ReceiptType;               // "Production", "ProductionSandbox", ...
payload.BundleId;                  // decoded attribute 2
payload.BundleIdBytes;             // its raw octets: the device-hash input
payload.ReceiptCreationDateMs;
payload.InApp[0].ProductId;
payload.InApp[0].ExpiresDateMs;
payload.UnknownAttributes;         // IReadOnlyDictionary<int, IReadOnlyList<byte[]>> in receipt order
payload.ToJson();                  // the canonical JSON every port shares
```

Decoding follows the rules every port shares: the first occurrence of an
attribute wins; every attribute that does not end up in a typed field (a
later copy, or a value that does not decode, whose field is then `null`) is
kept raw in `UnknownAttributes`, the in-app ones in that purchase's own; an
empty date string means "not set" and is not kept raw. `ToJson()` writes
keys in a fixed order, byte-identical across ports.

### `Failure` and `VerificationReason`

`Failure` is `{ Reason, Message, Cause }`; `Cause` is non-null only for
`UnreadablePayload` and `InternalError` — behind any other reason it would
be a parser exception about unverified input, whose message can quote raw
certificate text. Switch on `Failure.Reason`; never parse `Failure.Message`.
`VerificationReasonCodes.ToCode` gives the SCREAMING_SNAKE token every port
reports (e.g. `"UNTRUSTED_CHAIN"`) for logging or telemetry.

| `VerificationReason` | Raised when | Endpoint status |
|---|---|---|
| `Malformed` | the base64, ASN.1, CMS or JWS structure is broken, or a structural bound is exceeded | 21002 |
| `TooLarge` | the input is over its size cap and was not decoded | 21002 |
| `InvalidSignature` | the signature did not verify | 21003 |
| `UntrustedChain` | the chain does not reach a pinned root | 21003 |
| `InvalidCertificate` | a certificate does not decode, or is outside its validity window at the chain instant | 21003 |
| `InvalidCertificatePurpose` | a certificate lacks Apple's marker OID for its place | 21003 |
| `UnreadablePayload` | the chain and signature passed, but the signed content does not parse | 21009 |
| `InternalError` | the library failed unexpectedly, or the configured clock threw; no input makes a correct library answer it | 21009 |

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

The order is observable and is part of the contract: an input that fails an
early check reports that check's reason, not a later one.

**JWS.** Size cap → three segments, each strict base64url → header JSON
(strict UTF-8, no byte order mark, nothing but whitespace after the object),
`alg` ES256 and exactly three `x5c` entries → the certificates decode and
are structurally sound (X.509 version 1–3, no duplicate extension, no
undecodable extension) → the chain at `signedDate` (or the clock), the
intermediate checked against the pinned roots **before** the leaf is
checked against the intermediate → **leaf marker OID**
`1.2.840.113635.100.6.11.1` → **intermediate marker OID**
`1.2.840.113635.100.6.2.1` → the leaf's key is buildable on this platform →
ES256 signature. A chain that does not reach a pinned root is
`UntrustedChain` whatever markers it carries; validity is part of the chain
check, so an expired chain that lacks a marker, or has a broken signature,
is `InvalidCertificate` (owner decision, 2026-09-27). A key on a curve this
library cannot construct a key object from is `InvalidCertificate`, judged
only once its certificate has been vouched for and is about to be used —
this applies to the leaf and, separately, to the intermediate, since the
intermediate's own key is what checks the leaf.

**Receipt.** Size cap → strict base64 → CMS parse, including the syntax of
every `SignerInfo`'s signed attributes, whatever its position → at most four
`SignerInfo`s and ten embedded certificates → the creation date alone
(nothing else in the payload is read yet) → for each `SignerInfo`, in bag
order: the signer's certificate looked up among the embedded certificates by
issuer and serial number → structurally sound → the chain, top-down from the
pinned roots, at the creation date or the clock → **signer marker OID** →
**WWDR marker OID on the intermediate** → the signer's key buildable on this
platform → the CMS signature. One `SignerInfo` passing is enough; when none
does, the first one's failure is the verdict. Then the full payload parse,
where any failure is `UnreadablePayload`.

The receipt signer may use any algorithm `System.Security.Cryptography`
supports on this host: RSA PKCS#1 v1.5, RSA-PSS or ECDSA over MD5, SHA-1 or
the SHA-2 family (SHA-224 excepted — .NET ships no SHA-224 implementation
at all, on any target framework, so a receipt or certificate signed with it
cannot be verified on this port; no fixture requires it). A signer that
chains to a pinned root and carries Apple's marker is trusted whatever it
signs with, so a change on Apple's side does not reject genuine receipts.
The same goes for certificate signatures in the chain: this port accepts
any algorithm, like the Java and Node ports, rather than allowlisting a
fixed set (owner decision, 2026-09-27). A `signatureAlgorithm` that names a
hash (`sha256WithRSAEncryption`, `ecdsa-with-SHA384`, the RSA-PSS
parameters) must name the `SignerInfo`'s `digestAlgorithm`, or the signature
is `InvalidSignature`; `rsaEncryption` and `id-ecPublicKey` name none and
take the digest.

The bundled roots are checked against their published SHA-256 fingerprints
when they load, all three or none; `Config.Defaults()` throws if any do not
match, so a call made with a config it fails to produce would never exist.

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
`fixtures/cases-0.7.json` holds every port to these numbers from both
sides.

- **the endpoint request body and the receipt base64 string**: 3,145,728
  UTF-8 bytes. Over it is `TooLarge`, 21002 at the endpoint (Apple answers
  HTTP 413 there — check the body's length before the call to do the
  same).
- **the compact JWS**: 262,144 UTF-8 bytes, `TooLarge`.
- **JSON/ASN.1 nesting depth 64.** A deeper request body, JWS or CMS
  structure is `Malformed`.

`receipt-data` is decoded exactly as Apple's `verifyReceipt` accepts it:
standard base64 with canonical `=` padding and nothing else — whitespace,
base64url and omitted or extra padding are all refused, as at Apple. `x5c`
entries are standard base64, JWS segments unpadded canonical base64url, so
one signed payload has one accepted spelling.

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

## Known issue: legacy receipts on RHEL 9

The legacy Apple receipt chain and its CMS signature are SHA-1. On Linux,
`System.Security.Cryptography` uses the system OpenSSL, and RHEL 9's
DEFAULT crypto policy (also Alma and Rocky) makes that OpenSSL refuse SHA-1
signatures, so a genuine legacy receipt answers `UntrustedChain` there
however .NET was installed. Observed on AlmaLinux 9.8 with the distro .NET
8 on 2026-09-24. Windows and macOS use the OS crypto and are not affected
by this policy. Newer receipts (SHA-256 chains) and every JWS are
unaffected; FIPS mode is untested.

Until the fix ships, run `update-crypto-policies --set DEFAULT:SHA1` on
that host.

## Why offline

Signature verification cannot fail because a vendor endpoint is down, so a
purchase can be honoured immediately and reconciled against the App Store
Server API afterwards. Refunds and revocations still need that
reconciliation pass — a signature proves what Apple signed, not what
happened since.

This is one of nine implementations (Java, Node, Python, Swift, Go, Ruby,
Rust, PHP, .NET) that share a single fixture suite, including Apple's own
official test fixtures, and are required to agree byte for byte. See the
[project README](https://github.com/emindeniz99/apple-purchase-receipt-verifier#readme)
for the full picture and
[COMPARISON.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/COMPARISON.md)
for how it differs from Apple's official libraries.

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
| `AppleRootCertificates.JwsRoots()`, `AppleRootCertificates.ReceiptRoots()` | `AppleRootCertificates.Bundled()` (one set, shared by every method) |
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

The netstandard2.0 / net8.0 dual targeting, the compiled-in root
certificates, and the `System.Formats.Asn1`-only dependency set are
unchanged from 0.6.

## Testing

```bash
dotnet test dotnet/tests/ApplePurchaseReceiptVerifier.Tests           # the whole suite
dotnet test dotnet/tests/ApplePurchaseReceiptVerifier.Tests.Floor     # the netstandard2.0 asset, loaded into net8.0/9.0/10.0
```

`Conformance070.cs` runs every case in `fixtures/cases-0.7.json`, the
normative cross-language vector file every port of this library answers,
as one named test per case, and fails unless every case in the file ran.
The adapter carries no case-specific knowledge: it builds a `Config` from
the case, dispatches on the operation and evaluates the expected JSON
Pointers on the result. A case with a `maxMillis` budget is timed after a
warm-up call. `Tests.Floor` re-runs a representative slice of the same
fixtures with the library loaded as its netstandard2.0 asset, across
net8.0, net9.0 and net10.0 — proving the floor binary, not just the modern
one, decodes RSA-PSS and ECDSA correctly.

This environment is Linux-only: the Windows and macOS legs of the test
matrix (RHEL crypto-policy behaviour aside, which is Linux-specific by
definition) were not exercised here and need CI or a local run on those
platforms to confirm.

## Changelog

One version across every language —
[CHANGELOG.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/CHANGELOG.md)
/ [releases](https://github.com/emindeniz99/apple-purchase-receipt-verifier/releases).

## License

MIT.
