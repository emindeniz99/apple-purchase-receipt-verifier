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
    appAppleId: 1234567890,
    maxSignedAge: TimeSpan.FromMinutes(5));

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

Passing `deviceGuid` (the client's `identifierForVendor` bytes) additionally
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

// From a parsed body…
IReadOnlyDictionary<string, object?> response = endpoint.VerifyReceipt(body);

// …or straight from the wire.
string json = endpoint.VerifyReceiptJson(requestJson);
```

It never throws: the Apple status code is a field of the answer.

| Condition | `status` |
|---|---|
| body is not an object, or `receipt-data` is missing / not a string / empty / not base64 | `21002` |
| the receipt is malformed | `21002` |
| the receipt could not be authenticated | `21003` |
| an internal error | `21009` |
| a Production endpoint, and `receiptType ∉ {Production, ProductionVPP}` | `21007` |
| a Sandbox endpoint, and `receiptType ∈ {Production, ProductionVPP}` | `21008` |
| otherwise | `0`, plus `environment` and `receipt` |

Environment routing fails closed: only `Production` and `ProductionVPP` count
as production, so `ProductionVPPSandbox`, `Xcode` and a missing attribute all
route as non-production. Like Apple's endpoint, this does not check the bundle
id — compare `receipt.bundle_id` yourself. `password` and
`exclude-old-transactions` are accepted for wire compatibility and never read.
Fields that only exist in Apple's server-side subscription database
(`latest_receipt_info`, `pending_renewal_info`) are out of scope; see
`COMPARISON.md` in the repository.

## Error vocabulary

One exception type, `VerificationException`. Switch on `.Reason`; report
`.ReasonCode`, which is the canonical token every port emits.

| `VerificationReason` | `ReasonCode` | Raised when |
|---|---|---|
| `InvalidJwsFormat` | `INVALID_JWS_FORMAT` | not three dot-separated segments, `alg != ES256`, `x5c` absent or not exactly three, header or payload not base64url JSON |
| `InvalidCertificate` | `INVALID_CERTIFICATE` | an `x5c` entry is not base64, or not a parseable certificate |
| `InvalidCertificatePurpose` | `INVALID_CERTIFICATE_PURPOSE` | a required Apple marker OID is missing |
| `InvalidChain` | `INVALID_CHAIN` | the chain does not reach a pinned root at the signing time, an issuer is not a CA, the path is too long, or the receipt embeds more than ten certificates |
| `InvalidSignature` | `INVALID_SIGNATURE` | the ES256 or CMS signature check failed, or the key is of the wrong type |
| `WrongBundleId` | `WRONG_BUNDLE_ID` | the bundle id claim does not match |
| `WrongEnvironment` | `WRONG_ENVIRONMENT` | the environment / `receiptType` is outside the accepted set |
| `WrongAppAppleId` | `WRONG_APP_APPLE_ID` | a Production `AppTransaction` names a different app Apple id, or none is configured |
| `InvalidReceiptFormat` | `INVALID_RECEIPT_FORMAT` | not parseable CMS, trailing bytes, no payload, no `SignerInfo`, an unsupported digest, or a malformed attribute |
| `DeviceHashMismatch` | `DEVICE_HASH_MISMATCH` | the SHA-1 device binding failed, or the attributes it needs are absent |
| `StalePayload` | `STALE_PAYLOAD` | the payload is older than `maxSignedAge` |

The vocabulary is closed. Adding a twelfth reason is a change to every port and
to the shared schema in one pull request.

**Misconfiguration is not a verification verdict.** Empty trust anchors, an
empty bundle id, an empty accepted-environment set, or an endpoint environment
other than Production/Sandbox raise `ArgumentException` from the constructor.

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
  back to "now" there would move the validity verdict *and* skip the staleness
  rule.
- **Reject rather than repair.** An attribute type outside the 32-bit signed
  range, an integer wider than 64 bits, a date without a timezone designator, a
  value with trailing data, trailing bytes after the CMS blob or after the
  attribute set — each fails the receipt. Nothing is renamed or clamped onto a
  sentinel.
- **Bounded parsing.** At most ten embedded certificates, counted by a
  structural pre-scan before any certificate is decoded; at most six chain
  hops; bounded JSON depth and length; the payload double-unwrap is bounded at
  one, and a nested in-app attribute is recorded rather than recursed into.
- **Only this library's own exception escapes.** Containment is categorical,
  not a list of types: `AsnContentException` derives from `Exception` and not
  from `CryptographicException`, so a type-by-type catch leaks.
- **No logging, no metrics, no callbacks.** The reason code is the whole
  observability surface, and detail strings never carry receipt bytes, claims
  or key material.

## Time

There is one clock seam, `IClock`, and it is read in exactly two places:

1. the `STALE_PAYLOAD` comparison in `JwsVerifier`;
2. the `request_date` triple in `VerifyReceiptEndpoint`.

It never reaches a certificate-validity judgement. Where an input states no
signing time of its own, the validity instant falls back to the **system**
clock — so a caller injecting a clock, to pin a test or to work around skew,
cannot thereby accept a chain that is expired in real time. That is why
`ReceiptVerifier` takes no clock at all: it would have no legitimate consumer,
and an option with no consumer is an invitation to wire it into the one place
it must not reach.

```csharp
var verifier = new JwsVerifier(roots, bundleId, environments,
    maxSignedAge: TimeSpan.FromMinutes(5),
    clock: new FixedClock(DateTimeOffset.Parse("2025-01-01T00:00:00Z")));
```

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

Conformance: all 82 cases of `fixtures/cases.json`, with no skips.

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
