# ApplePurchaseReceiptVerifier (.NET)

Offline verification of Apple App Store purchase proofs:

- **StoreKit 2 / App Store Server JWS** — `signedTransactionInfo`,
  `signedRenewalInfo`, `AppTransaction`, Server Notifications V2.
- **Legacy PKCS#7 app receipts** — the blob apps used to POST to Apple's
  deprecated `verifyReceipt` endpoint, including a local, wire-compatible
  replacement for that endpoint.

Nothing here talks to the network, and nothing here reads the operating
system's trust store. Trust comes from the roots you pass in, or from the three
Apple roots compiled into the package.

This is the C# port of
[apple-purchase-receipt-verifier](https://github.com/emindeniz99/apple-purchase-receipt-verifier);
it answers the same `fixtures/cases.json` vectors as the Java, Node, Python and
Swift ports, byte for byte.

## Install

```
dotnet add package ApplePurchaseReceiptVerifier
```

Targets `netstandard2.0` and `net8.0`. The netstandard2.0 asset reaches .NET
Framework 4.6.2+, Mono 6.x and every .NET Core / .NET 5–10 runtime from one
binary; the net8.0 asset is trim- and AOT-annotated.

Dependencies: `System.Security.Cryptography.Pkcs` and `System.Formats.Asn1`,
both first-party. There is no JSON dependency — the package carries its own
bounded reader, because `System.Text.Json` is a NuGet package below net8.0 and
an assembly compiled against a newer one than the host ships will not load.

## Verifying a StoreKit 2 transaction

```csharp
using ApplePurchaseReceiptVerifier;
using ApplePurchaseReceiptVerifier.Jws;

var verifier = new JwsVerifier(
    trustedRoots: AppleRootCertificates.JwsRoots(),
    bundleId: "com.example.app",
    acceptedEnvironments: new[] { AppleEnvironment.Production, AppleEnvironment.Sandbox },
    appAppleId: 1234567890);

try
{
    TransactionPayload transaction = verifier.VerifyTransaction(jws);
    if (transaction.IsActiveAt(DateTimeOffset.UtcNow))
    {
        Grant(transaction.ProductId!, transaction.TransactionId!);
    }
}
catch (VerificationException e) when (e.Reason == VerificationReason.WrongEnvironment)
{
    // C# exception filters make the machine-readable reason a dispatch
    // mechanism: no string matching, no re-throw dance.
}
catch (VerificationException e)
{
    telemetry.Increment("iap.reject", e.ReasonCode);   // "INVALID_CHAIN"
}
```

Include `Sandbox` in the accepted set on any endpoint App Review can reach:
App Review runs production builds against the sandbox, so a single-environment
hard fail rejects purchases during review.

The other two entry points:

```csharp
AppTransactionPayload app = verifier.VerifyAppTransaction(jws);

// Chain and signature only — no claim is enforced. Use it for payload types
// without a dedicated model (renewal info, notification envelopes), and check
// bundleId / environment / appAppleId in the returned claims yourself.
IReadOnlyDictionary<string, object?> claims = verifier.VerifyRaw(jws);
```

Date claims are **epoch-millisecond integers**, exactly as Apple ships them —
`SignedDate`, `PurchaseDate`, `ExpiresDate`, `RevocationDate`,
`ReceiptCreationDate`. Converting them to `DateTimeOffset` would lose the raw
claim and put this port out of step with the other eight. Receipt *attribute*
dates are the opposite: those are `DateTimeOffset`.

`ClaimsMap` on either payload carries every claim, including ones this library
does not model.

## Verifying a legacy app receipt

```csharp
using ApplePurchaseReceiptVerifier.Receipt;

var verifier = new ReceiptVerifier(AppleRootCertificates.ReceiptRoots(), "com.example.app");

AppReceipt receipt = verifier.Verify(receiptBase64);
foreach (InAppPurchase purchase in receipt.InAppPurchases)
{
    Console.WriteLine($"{purchase.ProductId} {purchase.PurchaseDate:o}");
}
```

Every input form is reachable with and without the optional device binding:

```csharp
verifier.Verify(receiptDer);
verifier.Verify(receiptDer, deviceGuid);
verifier.Verify(receiptBase64);
verifier.Verify(receiptBase64, deviceGuid);
```

Passing `deviceGuid` (the client's device GUID — the raw bytes of
`identifierForVendor` on iOS, iPadOS, tvOS and watchOS, including an iOS
app running on an Apple silicon Mac, or the primary network interface's
MAC address from `copy_mac_address` on macOS and Mac Catalyst) additionally
enforces `SHA1(guid ‖ opaqueValue ‖ bundleIdBytes) == attribute 5`. It is
optional because a server does not always hold those bytes; cross-device
restore still works either way, since each device presents its own receipt.

Attribute types this library does not model are not dropped:
`receipt.UnknownAttributes[type]` hands back the verified-but-undecoded value
bytes, so a field Apple adds next year is reachable without a release.

`ReceiptVerifier` takes **no clock**, deliberately. See "Time" below.

### The primitive under both

```csharp
AppReceipt receipt = ReceiptVerifier.VerifyReceiptCore(receiptDer, roots);
```

Chain and signature, **without** the bundle-id check. The receipt it returns is
proved Apple-signed, but no claim in it has been checked — the bundle id in
particular is whatever the receipt says. Compare it yourself, or use
`Verify`.

## The verifyReceipt-compatible endpoint

A drop-in local replacement for Apple's deprecated endpoint: same request body,
same response body, same status codes, verified against pinned roots instead of
by calling Apple.

```csharp
var endpoint = new VerifyReceiptEndpoint(
    AppleRootCertificates.ReceiptRoots(), AppleEnvironment.Production);

VerifyReceiptResult result = endpoint.VerifyReceiptResult(body);   // a parsed body, or the raw JSON string
IReadOnlyDictionary<string, object?> response = result.ToResponse(); // Apple's body as a map
string json = result.ToJson();                                      // Apple's body as JSON

string json2 = endpoint.VerifyReceiptJson(requestJson);          // same as VerifyReceiptResult(requestJson).ToJson()
VerifyReceiptResult bare = endpoint.VerifyReceiptData(base64);   // receipt-data alone, no envelope
```

No endpoint method throws: the Apple status code is a field of the answer.

| Condition | `Status` | `FailureReason` |
|---|---|---|
| the raw body is over `MaxRequestBytes` (3,145,728 UTF-8 bytes); Apple answers HTTP 413 here | `21002` | `RequestTooLarge` |
| body is not a JSON object or nests deeper than 64, or `receipt-data` is missing, empty or not a string | `21002` | `MalformedRequest` |
| `receipt-data` is not canonical standard base64 (whitespace, base64url and omitted or extra padding all count, as at Apple), is over `MaxReceiptBytes`, or its CMS envelope does not parse | `21002` | `InvalidReceiptFormat` |
| the receipt could not be authenticated | `21003` | `InvalidChain`, `InvalidSignature`, other certificate reasons |
| the receipt authenticated but its signed content cannot be read, or an unexpected exception (including a throwing `IClock` or request dictionary, or a disposed endpoint). Not the client's fault: alert and retry or escalate, do not deny the user | `21009` | `InternalError`, with the parser's error or the exception in `FailureCause` |
| a Production endpoint, and `receiptType ∉ {Production, ProductionVPP}` | `21007` | none: `Receipt` is set |
| a Sandbox endpoint, and `receiptType ∈ {Production, ProductionVPP}` | `21008` | none: `Receipt` is set |
| otherwise | `0`, plus `environment` and `receipt` | none: `Receipt` is set |

A `VerifyReceiptResult` is one verification. `Status` is the answer for the
endpoint's own environment. `Receipt` is the verified `AppReceipt` whenever the
receipt bytes verified, 21007 and 21008 included, and `FailureReason` says why
there is no receipt; exactly one of the two is non-null. `IsVerified` is `true`
exactly when `Receipt` is non-null, and the compiler knows it
(`[MemberNotNullWhen]`), so `if (result.IsVerified)` gives a non-null
`result.Receipt`. That makes `IsVerified` **not** the same check as
`Status == 0`: `Status == 0` asks whether this endpoint's own environment
accepts the receipt, `IsVerified` asks whether the receipt verified at all. The
response is rendered only when `ToResponse()` or `ToJson()` is called, as a new
map each time. The result is immutable and thread-safe, and only the endpoint
can create one.

**Retrying in the other environment costs no second verification.**
`ToResponse(AppleEnvironment)` and `ToJson(AppleEnvironment)` render what an
endpoint of that environment would answer, recomputing the status from the
receipt's own type each time:

| receipt | on `Production` | on `Sandbox` |
|---|---|---|
| `Production`, `ProductionVPP` | 0 | 21008 |
| any other type, or none | 21007 | 0 |
| failed verification | its own status | its own status |

```csharp
VerifyReceiptResult result = production.VerifyReceiptResult(requestJson);
string json = result.Status == VerifyReceiptEndpoint.StatusSandboxReceiptOnProduction
    ? result.ToJson(AppleEnvironment.Sandbox)
    : result.ToJson();
```

A sandbox receipt never renders as a production 0, whichever endpoint verified
it. 21007 and 21008 bodies carry the status alone, as Apple's do. Any
environment other than `Production` or `Sandbox` throws `ArgumentException`,
the same refusal as the constructor's.

**`request_date`.** Every method takes an optional `DateTimeOffset? now`,
which becomes `request_date` in place of the endpoint's clock. Without one the
clock is read once, when the call is made, and `RequestDate` returns that
instant (in UTC). It reaches `request_date` and nothing else: certificate
validity never sees it (see [Time](#time)).

`VerifyReceiptResult(null)` does not compile, because both the dictionary and
the string overload match; cast the `null` to the one you mean.

Environment routing fails closed: only `Production` and `ProductionVPP` count
as production, so `ProductionVPPSandbox`, `Xcode` and a missing attribute all
route as non-production. Like Apple's endpoint, this does not check the bundle
id: compare `result.Receipt.BundleId` (or `receipt.bundle_id` in the body)
yourself before granting anything, or use `ReceiptVerifier`, which checks it
for you. `password` and `exclude-old-transactions` are accepted for wire
compatibility and never read. Fields that only exist in Apple's server-side
subscription database (`latest_receipt_info`, `pending_renewal_info`) are out
of scope; see `COMPARISON.md` in the repository.

## Error vocabulary

One exception type, `VerificationException`. Switch on `.Reason`; report
`.ReasonCode`, which is the canonical token every port emits.

| `VerificationReason` | `ReasonCode` | Raised when |
|---|---|---|
| `InvalidJwsFormat` | `INVALID_JWS_FORMAT` | not three dot-separated segments, `alg != ES256`, `x5c` absent or not exactly three, header or payload not base64url JSON |
| `InvalidCertificate` | `INVALID_CERTIFICATE` | an `x5c` entry is not canonical standard base64, or not a parseable certificate |
| `InvalidCertificatePurpose` | `INVALID_CERTIFICATE_PURPOSE` | a required Apple marker OID is missing |
| `InvalidChain` | `INVALID_CHAIN` | the chain does not reach a pinned root at the signing time, an issuer is not a CA, the path is too long, or the receipt embeds more than ten certificates |
| `InvalidSignature` | `INVALID_SIGNATURE` | the ES256 or CMS signature check failed, or the key is of the wrong type |
| `WrongBundleId` | `WRONG_BUNDLE_ID` | the bundle id claim does not match |
| `WrongEnvironment` | `WRONG_ENVIRONMENT` | the environment / `receiptType` is outside the accepted set |
| `WrongAppAppleId` | `WRONG_APP_APPLE_ID` | a Production `AppTransaction` names a different app Apple id, or none is configured |
| `InvalidReceiptFormat` | `INVALID_RECEIPT_FORMAT` | not parseable CMS, trailing bytes, no payload (a detached CMS), no `SignerInfo`, or an unsupported digest |
| `DeviceHashMismatch` | `DEVICE_HASH_MISMATCH` | the SHA-1 device binding failed, or the attributes it needs are absent |
| `InternalError` | `INTERNAL_ERROR` | the receipt's chain and signature verified, but its payload does not parse (`InnerException` is the parser's error); a verified JWS payload carries a claim `TransactionPayload` / `AppTransactionPayload` models with the wrong JSON type (a string that is not a string, an integer that is not a whole number in the property's range); or the host cannot run the device-hash check (SHA-1 unavailable). Not the client's fault: alert and retry or escalate, do not deny |

**Order of the receipt checks.** CMS parse → the creation date alone
(attribute 12; nothing else in the payload is decoded yet) → chain at that
date, or at the system clock when the date is missing, empty, unreadable or
stated twice → receipt-signing marker OID → CMS signature → full payload
parse → bundle id → device hash. Nothing is trusted before the chain and
the signature, so reading the date never rejects. The chain comes first so
the attacker's own key is never run before it is trusted. A payload that
fails the full parse was signed by a trusted signer, so it is
`InternalError`, not `InvalidReceiptFormat`.

The vocabulary is closed. Adding a twelfth reason is a change to every port
and to the shared schema in one pull request. `VerificationReason` also
carries `MalformedRequest` (`MALFORMED_REQUEST`) and `RequestTooLarge`
(`REQUEST_TOO_LARGE`), but only as
[`VerifyReceiptResult.FailureReason`](#the-verifyreceipt-compatible-endpoint)
values: no `VerificationException` is ever thrown with either, so a `switch`
over a caught exception's `Reason` never sees them. `InternalError` keeps the
position it had when it was endpoint-only, so no member's value moved.

**Misconfiguration is not a verification verdict.** Empty trust anchors, an
empty bundle id, an empty accepted-environment set, or an endpoint environment
other than Production/Sandbox raise `ArgumentException` from the constructor.

## Integrating: from verified payload to entitlement

The backend flow these calls sit inside is written out once in the
[project README](https://github.com/emindeniz99/apple-purchase-receipt-verifier#integrating-from-verified-payload-to-entitlement):
verify offline, deny on any failure, check the refund field, refresh a payload
past the freshness window, guard against replay on the transaction id, then
grant. That section also carries the policy table saying what each reason
means and which ones are worth an alert. Here are its two branches in this
port's API.

A StoreKit 2 signed transaction:

```csharp
using ApplePurchaseReceiptVerifier;
using ApplePurchaseReceiptVerifier.Jws;

public sealed class Redeem
{
    private readonly JwsVerifier verifier = new(
        trustedRoots: AppleRootCertificates.JwsRoots(),
        bundleId: "com.example.app",
        acceptedEnvironments: new[] { AppleEnvironment.Production, AppleEnvironment.Sandbox });

    public string RedeemTransaction(string userId, string jws)
    {
        TransactionPayload payload;
        try
        {
            payload = verifier.VerifyTransaction(jws);                  // step 2
        }
        catch (VerificationException e)
        {
            Log.Warning("purchase rejected: {Reason}", e.ReasonCode);
            return "denied";
        }

        if (payload.RevocationDate is not null) return "denied";        // step 3

        // step 4, your call: past the window, ask the client for a fresh
        // jwsRepresentation, or fetch one from the App Store Server API and
        // verify that instead
        long nowMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (nowMillis - (payload.SignedDate ?? 0) > 5 * 60 * 1000) return "refresh";

        string id = payload.TransactionId!;                             // step 5
        if (Grants.Exists(id)) return "denied";
        Grants.Record(id, payload.OriginalTransactionId, userId);

        Grant(userId, payload.ProductId!);
        return "granted";
    }
}
```

The legacy PKCS#7 app receipt is the same policy on the other input, the one
StoreKit 1 apps and older SDKs still send:

```csharp
using ApplePurchaseReceiptVerifier;
using ApplePurchaseReceiptVerifier.Receipt;

// Same policy keyed on the receipt's own dates. Verify takes the base64 the
// client sends or the DER bytes; VerifyReceiptEndpoint is the alternative,
// answering Apple's verifyReceipt JSON shape with a status instead.
public sealed class RedeemReceipt
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    private readonly ReceiptVerifier receipts =
        new(AppleRootCertificates.ReceiptRoots(), "com.example.app");

    public string Redeem(string userId, string receiptData, string productId)
    {
        AppReceipt receipt = receipts.Verify(receiptData);              // step 2
        DateTimeOffset now = DateTimeOffset.UtcNow;

        foreach (InAppPurchase purchase in receipt.InAppPurchases)
        {
            if (purchase.ProductId != productId) continue;
            if (purchase.CancellationDate is not null) return "denied"; // step 3
            if (purchase.ExpiresDate is { } expires && expires <= now) return "denied";

            // step 4: the same caller-side check, on the creation date. Past
            // the window, ask the client to refresh its receipt, or call the
            // App Store Server API by TransactionId and verify the JWS back.
            if (receipt.CreationDate is not { } created || now - created > Window)
            {
                return "refresh";
            }

            string id = purchase.TransactionId!;                        // step 5
            if (Grants.Exists(id)) return "denied";
            Grants.Record(id, purchase.OriginalTransactionId, userId);

            Grant(userId, purchase.ProductId!);
            return "granted";
        }

        return "denied";
    }
}
```

## Security posture

- **Pinned anchors only.** `X509Chain` is never constructed anywhere in this
  library, and a `BannedApiAnalyzers` rule makes writing one a compile error.
  Its defaults are the operating system's trust store plus online revocation
  and AIA fetching — and on a developer's macOS or Windows machine, where the
  Apple roots are already in the OS store, forgetting the pin fails
  *permissively*. A test asserts the shipped IL contains no reference to it.
- **No network.** No OCSP, no CRL, no AIA, no root download. Revocation is
  disabled by design; that is the accepted trade-off for offline verification,
  and it is what Apple's own libraries do in offline mode.
- **Apple marker OIDs are mandatory.** The JWS leaf must carry
  `1.2.840.113635.100.6.11.1` and the intermediate `1.2.840.113635.100.6.2.1`
  with `CA:true`; the receipt signer must carry `1.2.840.113635.100.6.11.1`.
  Without the last of these, any developer certificate chaining through the
  same WWDR intermediate could sign a forged receipt.
- **Validity is judged at signing time**, from the payload's `signedDate` /
  `receiptCreationDate` or the receipt's attribute-12 creation date, so a
  historical purchase signed with a since-rotated certificate keeps verifying.
  Every chain function takes that instant as a required parameter; there is no
  overload that defaults to "now". A payload stating a signing time no instant
  can represent is an `INVALID_CHAIN`, not a payload that states none: falling
  back to "now" there would move the validity verdict.
- **Reject rather than repair.** An attribute type outside the 32-bit signed
  range, an integer wider than 64 bits, a date without a timezone designator, a
  value with trailing data, trailing bytes after the CMS blob or after the
  attribute set — each fails the receipt. Nothing is renamed or clamped onto a
  sentinel.
- **Bounded parsing.** At most ten embedded certificates, counted by a
  structural pre-scan before any certificate is decoded; at most six chain
  hops; JSON nested at most 64 arrays and objects deep; the payload
  double-unwrap is bounded at one, and a nested in-app attribute is recorded
  rather than recursed into.
- **Input size caps, checked before anything is decoded.** The request and
  receipt caps are Apple's, fixed constants in every port of this library.
  Measured on 2026-09-23 against both of Apple's verifyReceipt endpoints
  (production and sandbox), a request body of 3,145,728 bytes is answered and
  one of 3,145,729 bytes gets HTTP 413. Apple counts UTF-8 bytes, not
  characters: 3,145,729 bytes of `é`, only 1,572,874 characters, also got 413.
  A raw request body passed to `VerifyReceiptEndpoint` may be at most
  `VerifyReceiptEndpoint.MaxRequestBytes` (3 MiB, 3,145,728 bytes); a larger
  one is 21002 with `REQUEST_TOO_LARGE`, decided before any parsing. One
  nested more than 64 levels deep is 21002 with `MALFORMED_REQUEST`. A receipt
  may be at most `ReceiptVerifier.MaxReceiptBytes` (3 MiB, 3,145,728 bytes),
  for the base64 string and for the DER; a larger one is
  `INVALID_RECEIPT_FORMAT`, and status 21002 at the endpoint. A compact JWS
  may be at most `JwsVerifier.MaxJwsBytes` (256 KiB, 262,144 characters); a
  longer one is `INVALID_JWS_FORMAT`. Decoding and parsing allocate in
  proportion to the input before any signature is checked, so without these a
  large enough input exhausts memory. Strings are measured in UTF-8 bytes
  without being encoded: more UTF-16 units than the limit is over it, three
  times the units within the limit is within it, and only a string between
  the two is walked, stopping at the first byte past the limit. A lone
  surrogate counts three bytes, as `Encoding.UTF8` counts it.
- **Answering 413 like Apple.** `RequestTooLarge` exists so an HTTP layer can
  send the status Apple sends. The body is Apple's 21002 either way:

  ```csharp
  VerifyReceiptResult result = endpoint.VerifyReceiptResult(rawRequestBody);
  int httpStatus = result.FailureReason == VerificationReason.RequestTooLarge ? 413 : 200;
  return Results.Content(result.ToJson(), "application/json", statusCode: httpStatus);
  ```

  A framework or proxy that caps request bodies itself has to allow at least
  3 MiB, or it refuses bodies Apple would answer.
- **Only this library's own exception escapes.** Containment is categorical,
  not a list of types: `AsnContentException` derives from `Exception` and not
  from `CryptographicException`, so a type-by-type catch leaks.
- **No logging, no metrics, no callbacks.** The reason code is the whole
  observability surface, and detail strings never carry receipt bytes, claims
  or key material.

## Time

There is one clock seam, `IClock`, and it is read in exactly one place: the
`request_date` triple in `VerifyReceiptEndpoint`.

It never reaches a certificate-validity judgement. Where an input states no
signing time of its own, the validity instant falls back to the **system**
clock, so a caller injecting a clock, to pin a test or to work around skew,
cannot thereby accept a chain that is expired in real time. That is why
`JwsVerifier` and `ReceiptVerifier` take no clock at all: they would have no
legitimate consumer, and an option with no consumer is an invitation to wire
it into the one place it must not reach.

```csharp
var endpoint = new VerifyReceiptEndpoint(roots, AppleEnvironment.Sandbox,
    new FixedClock(DateTimeOffset.Parse("2025-01-01T00:00:00Z")));
```

**Freshness is your call.** No payload is rejected for its age, as in Apple's
own App Store Server Libraries: `signedDate` only decides the instant the
chain is judged at. The right limit depends on the endpoint (Apple retries a
server notification for days, and a device may present an old but genuine
payload), so apply one yourself where it fits:
`bool tooOld = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (transaction.SignedDate ?? 0) > 300_000;`

## Lifetime

The verifiers copy the anchors you pass in, so you may dispose yours. They are
immutable and thread-safe once constructed — register one as a singleton. They
implement `IDisposable` to release the copies' handles; that matters only if
you build one per request.

## What this cannot tell you

A signature proves what Apple signed, and nothing about what happened
afterwards. Refunds, revocations after the fact and replayed receipts are not
detectable from the bytes. Track transaction ids server-side, and use Apple's
server API for current subscription state.

Verifying receipts inside a client is an anti-pattern whatever the language:
the attacker owns the client. This package is meant for a server.

## Support and testing

Conformance: every case in `fixtures/cases.json`, with no skips.

Beyond that the suite covers the anti-forgery matrix against a generated fake
Apple PKI, a mutation sweep over the genuine receipt and JWS fixtures, the
resource bounds, the .NET-specific hazards (a hostile thread culture, the
ECDSA DER-versus-P1363 trap, thread safety, disposal), and the whole public
surface re-run against the netstandard2.0 asset.

Unity is **not** a supported target yet. The netstandard2.0 asset is built to
be IL2CPP-friendly — no reflection-based serialization, roots as compiled-in
source constants rather than resources, no `System.Text.Json` — but nobody has
run this suite inside a real Unity IL2CPP player, so the claim stays off the
list until someone does.

## License

MIT.
